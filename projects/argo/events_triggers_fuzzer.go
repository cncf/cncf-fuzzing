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

package triggers

import (
        "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
        fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzConstructPayload(data []byte) int {
        f := fuzz.NewConsumer(data)
        events := make(map[string]*v1alpha1.Event)
        err := f.FuzzMap(&events)
        if err != nil {
                return 0
        }
        parameters := make([]v1alpha1.TriggerParameter, 0)
        err = f.FuzzMap(&parameters)
        if err != nil {
                return 0
        }
        _, _ = ConstructPayload(events, parameters)
        return 1
}