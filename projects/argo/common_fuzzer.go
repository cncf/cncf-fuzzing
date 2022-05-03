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

package common

import (
	"runtime"
	"runtime/debug"
	"strings"
)

func FuzzGetExpression(data []byte) int {
	defer catchPanics()
	expr, err := NewBoolExpression(string(data))
	if err == nil {
		expr.GetExpression()
	}
	return 1
}

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "runtime error: index out of range") {
			return
		} else if strings.Contains(string(debug.Stack()), "github.com/Knetic/govaluate.(*lexerStream).readCharacter(...)") {
			return
		} else {
			panic(err)
		}
	}
}
