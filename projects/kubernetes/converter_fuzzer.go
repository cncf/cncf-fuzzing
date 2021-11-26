// Copyright 2021 ADA Logics Ltd
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

package fuzzing

import (
	"fmt"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"reflect"
	"time"
)

type A struct {
	A int    `json:"aa,omitempty"`
	B string `json:"ab,omitempty"`
	C bool   `json:"ac,omitempty"`
}

type F struct {
	A string            `json:"fa"`
	B map[string]string `json:"fb"`
	C []A               `json:"fc"`
	D int               `json:"fd"`
	E float32           `json:"fe"`
	F []string          `json:"ff"`
	G []int             `json:"fg"`
	H []bool            `json:"fh"`
	I []float32         `json:"fi"`
}

func FuzzUnrecognized(data []byte) int {
	_ = doUnrecognized(string(data), &F{})
	return 1
}

var simpleEquality = conversion.EqualitiesOrDie(
	func(a, b time.Time) bool {
		return a.UTC() == b.UTC()
	},
)

// Verifies that:
// 1) serialized json -> object
// 2) serialized json -> map[string]interface{} -> object
// produces the same object.
func doUnrecognized(jsonData string, item interface{}) error {
	unmarshalledObj := reflect.New(reflect.TypeOf(item).Elem()).Interface()
	err := json.Unmarshal([]byte(jsonData), unmarshalledObj)
	if err != nil {
		return err
	}

	unstr := make(map[string]interface{})
	err = json.Unmarshal([]byte(jsonData), &unstr)
	if err != nil {
		return err
	}
	newObj := reflect.New(reflect.TypeOf(item).Elem()).Interface()
	err = runtime.NewTestUnstructuredConverter(simpleEquality).FromUnstructured(unstr, newObj)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(unmarshalledObj, newObj) {
		panic(fmt.Sprintf("DeepEqual failed\n"))
	}
	return nil
}
