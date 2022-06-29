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

package elf

import (
	"os"
)

func FuzzElfOpen(data []byte) int {
	f, err := os.Create("test_elf")
	if err != nil {
		os.Remove("test_elf")
		return 0
	}
	defer f.Close()
	defer os.Remove("test_elf")
	f.Write(data)
	e, err := Open("test_elf")
	if err == nil {
		e.Close()
	}
	return 1
}
