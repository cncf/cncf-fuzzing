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

package parser

import (
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	payloads = map[int]string{
		0: "PerfEvent",
		1: "AgentEvent",
		2: "LostEvent",
	}
)

func FuzzParserDecode(data []byte) int {
	p, err := New(nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return 0
	}

	f := fuzz.NewConsumer(data)
	payloadType, err := f.GetInt()
	if err != nil {
		return 0
	}

	mo := &observerTypes.MonitorEvent{}

	switch payloads[payloadType%len(payloads)] {
	case "PerfEvent":
		pe := &observerTypes.PerfEvent{}
		f.GenerateStruct(pe)
		mo.Payload = pe
	case "AgentEvent":
		ae := &observerTypes.AgentEvent{}
		f.GenerateStruct(ae)
		mo.Payload = ae
	case "LostEvent":
		le := &observerTypes.LostEvent{}
		f.GenerateStruct(le)
		mo.Payload = le
	}
	_, _ = p.Decode(mo)
	return 0
}
