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

package expr

import (
        "encoding/json"
        fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzExpr(data []byte) int {
        f := fuzz.NewConsumer(data)
        input, err := f.GetString()
        if err != nil {
                return 0
        }
        d, err := f.GetBytes()
        if err != nil {
        }
        env := make(map[string]interface{})
        err = json.Unmarshal(d, &env)
        if err != nil {
                return 0
       }
        _, _ = EvalBool(input, env)
        return 1
}
