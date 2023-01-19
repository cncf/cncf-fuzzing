// Copyright 2023 the cncf-fuzzing authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package keydbstore

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	_ "github.com/mattn/go-sqlite3"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/utils"
)

var gormActiveTimeFuzz = time.Date(2016, 12, 31, 1, 1, 1, 0, time.UTC)

var (
	roleNames = []data.RoleName{data.CanonicalRootRole,
		data.CanonicalTargetsRole,
		data.CanonicalSnapshotRole,
		data.CanonicalTimestampRole}
)

func sqlite3Setup_Fuzz() (*SQLKeyDBStore, func(), error) {
	tempBaseDir, err := ioutil.TempDir("", "notary-test-")
	if err != nil {
		panic("Could not create tempdir")
	}

	dbStore, err := SetupSQLDB_Fuzz("sqlite3", filepath.Join(tempBaseDir, "test_db"))
	if err != nil {
		return nil, func() {}, err
	}
	var cleanup = func() {
		dbStore.db.Close()
		os.RemoveAll(tempBaseDir)
	}
	if dbStore.Name() != "sqlite3" {
		panic("Failed creating an sqlite3 db")
	}
	return dbStore, cleanup, nil
}

func SetupSQLDB_Fuzz(dbtype, dburl string) (*SQLKeyDBStore, error) {
	dbStore, err := NewSQLKeyDBStore(multiAliasRetriever, validAliases[0], dbtype, dburl)
	if err != nil {
		return nil, err
	}
	dbStore.nowFunc = func() time.Time { return gormActiveTimeFuzz }

	// Create the DB tables if they don't exist
	dbStore.db.CreateTable(&GormPrivateKey{})

	// verify that the table is empty
	var count int
	query := dbStore.db.Model(&GormPrivateKey{}).Count(&count)
	if query.Error != nil {
		return nil, query.Error
	}
	if count != 0 {
		panic("count should not be nil. This is an error in the fuzzer.")
	}

	return dbStore, nil
}

func FuzzKeyDBStore(f *testing.F) {
	f.Fuzz(func(t *testing.T, fuzzData []byte) {
		ff := fuzz.NewConsumer(fuzzData)

		testKeys := make([]data.PrivateKey, 0)
		noOfTestKeys, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		for i := 0; i < noOfTestKeys%20; i++ {
			readerData, err := ff.GetBytes()
			if err != nil {
				t.Skip()
			}
			testKey, err := utils.GenerateECDSAKey(bytes.NewReader(readerData))
			if err != nil {
				t.Skip()
			}
			testKeys = append(testKeys, testKey)
		}
		if len(testKeys) == 0 {
			t.Skip()
		}

		dbStore, cleanup, err := sqlite3Setup_Fuzz()
		if err != nil {
			fmt.Println(err)
			t.Fatal("Could not create the db. This is not a fuzz issue.")
		}
		defer cleanup()

		for i := 0; i < len(testKeys); i++ {
			testKey := testKeys[i]

			// Add keys to the DB
			roleInd, err := ff.GetInt()
			if err != nil {
				t.Skip()
			}
			err = dbStore.AddKey(roleNames[roleInd%len(roleNames)], "gun", testKey)
			if err != nil {
				t.Skip()
			}
		}

		noOfCalls, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		for i := 0; i < noOfCalls%10; i++ {
			typeOfCall, err := ff.GetInt()
			if err != nil {
				t.Skip()
			}
			switch typeOfCall % 4 {
			case 0:
				keyInd, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				if len(testKeys) != 0 {
					dbStore.RemoveKey(testKeys[keyInd%len(testKeys)].ID())
				}
			case 1:
				keyInd, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				if len(testKeys) != 0 {
					_, _, _ = dbStore.GetPrivateKey(testKeys[keyInd%len(testKeys)].ID())
				}
			case 2:
				keyInd, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				if len(testKeys) != 0 {
					newValidAlias, err := ff.GetString()
					if err != nil {
						t.Skip()
					}
					_ = dbStore.RotateKeyPassphrase(testKeys[keyInd%len(testKeys)].ID(), newValidAlias)
				}
			case 3:
				dbStore.HealthCheck()
			}
		}
	})
}
