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

package dtmanager

import (

	"github.com/kubeedge/beehive/pkg/core/model"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/kubeedge/kubeedge/edge/pkg/devicetwin/dtcontext"
)

var fuzzActions = map[int]string {
	0: "dealTwinUpdate",
	1: "dealTwinGet",
	2: "dealTwinSync",
	3: "dealDeviceAttrUpdate",
	4: "dealDeviceStateUpdate",
	5: "dealSendToCloud",
	6: "dealSendToEdge",
	7: "dealLifeCycle",
	8: "dealConfirm",
	9: "dealMembershipGet",
	10: "dealMembershipUpdate",
	11: "dealMembershipDetail",
}

func FuzzdealTwinActions(data []byte) int {
	f := fuzz.NewConsumer(data)
	device, err := f.GetString()
	if err != nil {
		return 0
	}
	content, err := f.GetBytes()
	if err != nil {
		return 0
	}
	actionType, err := f.GetInt()
	if err != nil {
		return 0
	}
	msg := &model.Message{
		Content: content,
	}
	context, _ := dtcontext.InitDTContext()
	switch fuzzActions[actionType%len(fuzzActions)] {
	case "dealTwinUpdate":
		dealTwinUpdate(context, device, msg)
	case "dealTwinGet":
		dealTwinGet(context, device, msg)
	case "dealTwinSync":
		dealTwinSync(context, device, msg)
	case "dealDeviceAttrUpdate":
		dealDeviceAttrUpdate(context, device, msg)
	case "dealDeviceStateUpdate":
		dealDeviceStateUpdate(context, device, msg)
	case "dealSendToCloud":
		dealSendToCloud(context, device, msg)
	case "dealSendToEdge":
		dealSendToEdge(context, device, msg)
	case "dealLifeCycle":
		dealLifeCycle(context, device, msg)
	case "dealConfirm":
		dealConfirm(context, device, msg)
	case "dealMembershipGet":
		dealMembershipGet(context, device, msg)
	case "dealMembershipUpdate":
		dealMembershipUpdate(context, device, msg)
	case "dealMembershipDetail":
		dealMembershipDetail(context, device, msg)
	}
	return 1
}