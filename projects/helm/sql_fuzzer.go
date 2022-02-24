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
	"testing"
	rspb "helm.sh/helm/v3/pkg/release"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzSqlDriver(data []byte) int {
	rel1 := &rspb.Release{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(rel1)
	if err != nil {
		return 0
	}
	key1, err := f.GetString()
	if err != nil {
		return 0
	}
	rel2 := &rspb.Release{}
	err = f.GenerateStruct(rel2)
	if err != nil {
		return 0
	}
	rel3 := &rspb.Release{}
	err = f.GenerateStruct(rel3)
	if err != nil {
		return 0
	}
	key2, err := f.GetString()
	if err != nil {
		return 0
	}
	key3, err := f.GetString()
	if err != nil {
		return 0
	}
	key4, err := f.GetString()
	if err != nil {
		return 0
	}
	key5, err := f.GetString()
	if err != nil {
		return 0
	}
	key6, err := f.GetString()
	if err != nil {
		return 0
	}
	labels := make(map[string]string)
	err = f.FuzzMap(&labels)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	sqlDriver, _ := newTestFixtureSQL(t)
	defer sqlDriver.db.Close()
	
	sqlDriver.Create(key1, rel1)
	sqlDriver.Create(key2, rel2)
	sqlDriver.Get(key3)
	sqlDriver.Get(key4)
	sqlDriver.Update(key5, rel3)
	sqlDriver.Query(labels)
	sqlDriver.Delete(key6)
	return 1
}