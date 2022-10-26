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

package format

import (
	"runtime"

	"github.com/cilium/cilium/pkg/monitor/payload"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

/*
This fuzzer invokes the garbage collector, because
fmt.Sprintf() seemingly will not free memory between
runs. The GC slows down the fuzzer significantly.
*/
func FuzzFormatEvent(data []byte) int {
	f := fuzz.NewConsumer(data)
	pl := &payload.Payload{}
	err := f.GenerateStruct(pl)
	if err != nil {
		return 0
	}

	// Invalid pl.Data. Leave here to avoid
	// invoking the GC.
	if len(pl.Data) == 0 {
		return 0
	}

	defer func() {
		if r := recover(); r != nil {
		}
		runtime.GC()
	}()

	mf := NewMonitorFormatter(0, nil)

	mf.FormatEvent(pl)
	return 1
}
