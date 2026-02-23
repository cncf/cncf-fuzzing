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

package colldata

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzCollations(data []byte) int {
	testinit()
	f := fuzz.NewConsumer(data)
	collIndex, err := f.GetInt()
	if err != nil {
		return 0
	}
	coll := testcollationSlice[collIndex%len(testcollationSlice)]
	left, err := f.GetBytes()
	if err != nil {
		return 0
	}
	right, err := f.GetBytes()
	if err != nil {
		return 0
	}
	_ = coll.Collate(left, right, false)
	_ = coll.Collate(left, right, true)
	numCodepoints, _ := f.GetInt()
	_ = coll.WeightString(nil, left, numCodepoints%100)
	return 1
}
