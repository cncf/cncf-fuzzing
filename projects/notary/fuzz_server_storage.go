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

package storage

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	_ "github.com/mattn/go-sqlite3"
	"github.com/theupdateframework/notary/tuf/data"
)

func SetupSQLDBFuzz(dbtype, dburl string) *SQLStorage {
	dbStore, err := NewSQLStorage(dbtype, dburl)
	if err != nil {
		panic(err)
	}

	// Create the DB tables
	err = CreateTUFTable(dbStore.DB)
	if err != nil {
		panic(err)
	}
	err = CreateChangefeedTable(dbStore.DB)
	if err != nil {
		panic(err)
	}

	// verify that the tables are empty
	var count int
	query := dbStore.DB.Model(&TUFFile{}).Count(&count)
	if query.Error != nil {
		panic(query.Error)
	}
	if count != 0 {
		panic("count should be 0")
	}
	return dbStore
}

func sqlite3SetupFuzz() (*SQLStorage, func()) {
	tempBaseDir, err := ioutil.TempDir("", "notary-test-")
	if err != nil {
		panic(err)
	}

	dbStore := SetupSQLDBFuzz("sqlite3", filepath.Join(tempBaseDir, "test_db"))
	var cleanup = func() {
		dbStore.DB.Close()
		os.RemoveAll(tempBaseDir)
	}
	return dbStore, cleanup
}

func FuzzServerStorageSQL(f *testing.F) {
	f.Fuzz(func(t *testing.T, fuzzData []byte) {
		ff := fuzz.NewConsumer(fuzzData)

		var noOfMetas int
		var err error
		var gunName string
		sTufMetas := make([]StoredTUFMeta, 0)
		noOfMetas, err = ff.GetInt()
		if err != nil {
			t.Skip()
		}
		noOfCalls, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		if noOfCalls == 0 {
			noOfCalls = 1
		}
		for i := 0; i < noOfCalls%20; i++ {
			noOfMetas, err = ff.GetInt()
			if err != nil {
				t.Skip()
			}
			if noOfMetas == 0 {
				noOfMetas = 1
			}
			for j := 0; j < noOfMetas%5; j++ {
				sm := StoredTUFMeta{}
				err := ff.GenerateStruct(&sm)
				if err != nil {
					t.Skip()
				}
				sTufMetas = append(sTufMetas, sm)
			}
		}

		if len(sTufMetas) == 0 {
			t.Skip()
		}

		noOfCalls, err = ff.GetInt()
		if err != nil {
			t.Skip()
		}
		if noOfCalls == 0 {
			noOfCalls = 1
		}
		dbStore, cleanup := sqlite3SetupFuzz()
		defer cleanup()
		for i := 0; i < noOfCalls%20; i++ {
			callType, err := ff.GetInt()
			if err != nil {
				t.Skip()
			}
			switch callType % 4 {
			case 0:
				ind, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				gunName, err = ff.GetString()
				if err != nil {
					t.Skip()
				}
				dbStore.UpdateCurrent(data.GUN(gunName), MakeUpdate(sTufMetas[ind%len(sTufMetas)]))
				dbStore.Delete(data.GUN(gunName))
			case 1:
				gunName, err = ff.GetString()
				if err != nil {
					t.Skip()
				}
				dbStore.Delete(data.GUN(gunName))
			case 2:
				dbStore.CheckHealth()
			case 3:
				changeID, err := ff.GetString()
				if err != nil {
					t.Skip()
				}
				_, err = strconv.ParseInt(changeID, 10, 32)
				if err != nil {
					continue
				}
				records, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				filterName, err := ff.GetString()
				if err != nil {
					t.Skip()
				}
				_, _ = dbStore.GetChanges(changeID, records, filterName)
			}
		}
	})
}

func FuzzServerStorageMemStorage(f *testing.F) {
	f.Fuzz(func(t *testing.T, fuzzData []byte) {
		ff := fuzz.NewConsumer(fuzzData)

		var noOfMetas int
		var err error
		var gunName string
		sTufMetas := make([]StoredTUFMeta, 0)
		noOfMetas, err = ff.GetInt()
		if err != nil {
			t.Skip()
		}
		noOfCalls, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		if noOfCalls == 0 {
			noOfCalls = 1
		}
		for i := 0; i < noOfCalls%20; i++ {
			noOfMetas, err = ff.GetInt()
			if err != nil {
				t.Skip()
			}
			if noOfMetas == 0 {
				noOfMetas = 1
			}
			for j := 0; j < noOfMetas%5; j++ {
				sm := StoredTUFMeta{}
				err := ff.GenerateStruct(&sm)
				if err != nil {
					t.Skip()
				}
				sTufMetas = append(sTufMetas, sm)
			}
		}

		if len(sTufMetas) == 0 {
			t.Skip()
		}

		noOfCalls, err = ff.GetInt()
		if err != nil {
			t.Skip()
		}
		if noOfCalls == 0 {
			noOfCalls = 1
		}
		dbStore := NewMemStorage()
		for i := 0; i < noOfCalls%20; i++ {
			callType, err := ff.GetInt()
			if err != nil {
				t.Skip()
			}
			switch callType % 4 {
			case 0:
				ind, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				gunName, err = ff.GetString()
				if err != nil {
					t.Skip()
				}
				dbStore.UpdateCurrent(data.GUN(gunName), MakeUpdate(sTufMetas[ind%len(sTufMetas)]))
				dbStore.Delete(data.GUN(gunName))
			case 1:
				gunName, err = ff.GetString()
				if err != nil {
					t.Skip()
				}
				dbStore.Delete(data.GUN(gunName))
			case 2:

			case 3:
				changeID, err := ff.GetString()
				if err != nil {
					t.Skip()
				}
				_, err = strconv.ParseInt(changeID, 10, 32)
				if err != nil {
					continue
				}
				records, err := ff.GetInt()
				if err != nil {
					t.Skip()
				}
				filterName, err := ff.GetString()
				if err != nil {
					t.Skip()
				}
				_, _ = dbStore.GetChanges(changeID, records, filterName)
			}
		}
	})
}

func FuzzServerStorageTufStorage(f *testing.F) {
	f.Fuzz(func(t *testing.T, fuzzData []byte, dataName string) {
		role, gun := data.CanonicalRootRole, data.GUN(dataName)
		rec := SampleCustomTUFObj(gun, role, 1, nil)

		dbStore, cleanup := sqlite3SetupFuzz()
		defer cleanup()
		s := NewTUFMetaStorage(dbStore)
		_, _, _ = s.GetCurrent(rec.Gun, rec.Role)
		_, _, _ = s.MetaStore.GetCurrent(rec.Gun, rec.Role)

	})
}
