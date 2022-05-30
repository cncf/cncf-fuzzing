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

package csidriver

// This fuzzer mimicks the usage of extractMessage() found here:
// https://github.com/kubeedge/kubeedge/blob/master/cloud/pkg/csidriver/utils.go.
func FuzzextractMessage(data []byte) int {
	result, err := extractMessage(string(data))
	if err == nil {
		_ = result.GetContent().(string)
		_ = result.GetOperation()
	}
	return 1
}