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

package devices

import (
	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"strings"
)

func Fuzz(data []byte) int {
	c := gofuzzheaders.NewConsumer(data)
	str1, err := c.GetString()
	if err != nil {
		return -1
	}
	reader1 := strings.NewReader(str1)
	emu1, err := EmulatorFromList(reader1)
	if err != nil {
		return -1
	}

	str2, err := c.GetString()
	if err != nil {
		return -1
	}
	reader2 := strings.NewReader(str2)
	emu2, err := EmulatorFromList(reader2)
	if err != nil {
		return -1
	}
	emu1.Transition(emu2)
	return 1
}
