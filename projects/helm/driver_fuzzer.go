//go:build gofuzz
// +build gofuzz

// Copyright 2022 ADA Logics Ltd
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

package driver

import (
	"fmt"
	"testing"
	rspb "helm.sh/helm/v4/pkg/release/v1"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzSqlDriver(data []byte) int {
	f := fuzz.NewConsumer(data)

	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}	
	t := &testing.T{}
	sqlDriver, _ := newTestFixtureSQL(t)
	defer sqlDriver.db.Close()
	for i:=0;i<noOfCalls%10;i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType%6 {
		case 0:
			rel := &rspb.Release{}
			err := f.GenerateStruct(rel)
			if err != nil {
				return 0
			}
			relName, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz0123456789-.", 52)
		    if err != nil {
		            return 0
		    }
		    rel.Name = relName
		    rel.Info.Status = rspb.StatusDeployed
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			sqlDriver.Create(key, rel)
		case 1:			
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			sqlDriver.Get(key)
		case 2:			
			rel := &rspb.Release{}
			err = f.GenerateStruct(rel)
			if err != nil {
				return 0
			}
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			sqlDriver.Update(key, rel)
		case 3:
			labels := make(map[string]string)
			err = f.FuzzMap(&labels)
			if err != nil {
				return 0
			}
			sqlDriver.Query(labels)
		case 4:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			sqlDriver.Delete(key)
		case 5:
			_, _ = sqlDriver.List(func(rel *rspb.Release) bool {
				if rel.Info == nil {
					return false
				}
				return rel.Info.Status == rspb.StatusUninstalled
			})
		}
	}	
	return 1
}

func FuzzRecords(data []byte) int {
	f := fuzz.NewConsumer(data)
	rls1 := &rspb.Release{}
	err := f.GenerateStruct(rls1)
	if err != nil {
		return 0
	}
	key1, err := f.GetString()
	if err != nil {
		return 0
	}
	rls2 := &rspb.Release{}
	err = f.GenerateStruct(rls2)
	if err != nil {
		return 0
	}
	key2, err := f.GetString()
	if err != nil {
		return 0
	}
	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	r1 := newRecord(key1, rls1)
	r2 := newRecord(key2, rls2)
	rs := records([]*record{r1, r2})
	for i:=0;i<noOfCalls%10;i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType%6 {
		case 0:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_ = rs.Get(key)
		case 1:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_ = rs.Exists(key)
		case 2:
			key1, err := f.GetString()
			if err != nil {
				return 0
			}
			key2, err := f.GetString()
			if err != nil {
				return 0
			}
			rls := &rspb.Release{}
			err = f.GenerateStruct(rls)
			if err != nil {
				return 0
			}

			_ = rs.Replace(key1, newRecord(key2, rls))
		case 3:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_ = rs.Remove(key)
		case 4:
			_ = rs.Len()
		case 5:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			rls := &rspb.Release{}
			err = f.GenerateStruct(rls)
			if err != nil {
				return 0
			}
			_ = rs.Add(newRecord(key, rls))
		}
	}
	return 1
}

func FuzzSecrets(data []byte) int {
	f := fuzz.NewConsumer(data)
	rls1 := &rspb.Release{}
	err := f.GenerateStruct(rls1)
	if err != nil {
		return 0
	}
	rls2 := &rspb.Release{}
	err = f.GenerateStruct(rls2)
	if err != nil {
		return 0
	}

	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}

	t := &testing.T{}
	secrets := newTestFixtureSecrets(t, rls1, rls2)

	for i:=0;i<noOfCalls%10;i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType%6 {
		case 0:
			rls := &rspb.Release{}
			err = f.GenerateStruct(rls)
			if err != nil {
				return 0
			}
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			secrets.Create(key, rls)
		case 1:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = secrets.Get(key)
		case 2:
			rls := &rspb.Release{}
			err = f.GenerateStruct(rls)
			if err != nil {
				return 0
			}
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			secrets.Update(key, rls)
		case 3:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = secrets.Delete(key)
		case 4:
			_, _ = secrets.List(func(rel *rspb.Release) bool {
				return rel.Info.Status == rspb.StatusUninstalled
			})
		case 5:
			labels := make(map[string]string)
			err := f.FuzzMap(&labels)
			if err != nil {
				return 0
			}
			_, _ = secrets.Query(labels)
		}
	}
	return 1
}

func FuzzMemory(data []byte) int {
	f := fuzz.NewConsumer(data)
	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	mem := NewMemory()
	for i:=0;i<noOfCalls%10;i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType%6 {
		case 0:
			rs := &rspb.Release{}
			err := f.GenerateStruct(rs)
			if err != nil {
				return 0
			}
			mem.Create(testFuzzKey(rs.Name, rs.Version), rs)
		case 1:
			newNameSpace, err := f.GetString()
			if err != nil {
				return 0
			}
			mem.SetNamespace(newNameSpace)
		case 2:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = mem.Delete(key)
		case 3:
			keyvals := make(map[string]string)
			err := f.FuzzMap(&keyvals)
			if err != nil {
				return 0
			}
			_, _ = mem.Query(keyvals)
		case 4:
			rs := &rspb.Release{}
			err := f.GenerateStruct(rs)
			if err != nil {
				return 0
			}
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			mem.Update(key, rs)
		case 5:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = mem.Get(key)
		}
	}
	return 1
}

func testFuzzKey(name string, vers int) string {
	return fmt.Sprintf("%s.v%d", name, vers)
}

func FuzzCfgmaps(data []byte) int {
	f := fuzz.NewConsumer(data)
	rls1 := &rspb.Release{}
	err := f.GenerateStruct(rls1)
	if err != nil {
		return 0
	}
	rls2 := &rspb.Release{}
	err = f.GenerateStruct(rls2)
	if err != nil {
		return 0
	}
	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	t := &testing.T{}
	cfgmaps := newTestFixtureCfgMaps(t, rls1, rls2)
	for i:=0;i<noOfCalls%10;i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType%6 {
		case 0:
			_, _ = cfgmaps.List(func(rel *rspb.Release) bool {
				return rel.Info.Status == rspb.StatusUninstalled
			})
		case 1:
			labels := make(map[string]string)
			err := f.FuzzMap(&labels)
			if err != nil {
				return 0
			}
			_, _ = cfgmaps.Query(labels)
		case 2:
			rls := &rspb.Release{}
			err := f.GenerateStruct(rls)
			if err != nil {
				return 0
			}
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			cfgmaps.Create(key, rls)
		case 3:
			rls := &rspb.Release{}
			err := f.GenerateStruct(rls)
			if err != nil {
				return 0
			}
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			cfgmaps.Update(key, rls)
		case 4:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			cfgmaps.Delete(key)
		case 5:
			key, err := f.GetString()
			if err != nil {
				return 0
			}
			cfgmaps.Get(key)
		}
	}
	return 1
}
