// Copyright 2023 the cncf-fuzzing authors
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

package availabilitynodepriority

import (
	"context"
	"k8s.io/apimachinery/pkg/types"
	state "knative.dev/eventing/pkg/scheduler/state"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzAvailabilityNodePriorityScore(f *testing.F) {
	f.Fuzz(func(t *testing.T, args string, data []byte) {
		ff := fuzz.NewConsumer(data)
		args, err := ff.GetString()
		if err != nil {
			return
		}
		states := &state.State{}
		ff.GenerateStruct(states)

		key := &types.NamespacedName{}
		ff.GenerateStruct(key)

		podID, err := ff.GetInt()
		if err != nil {
			return
		}

		feasiblePods := make([]int32, 0)
		noOfFP, err := ff.GetInt()
		if err != nil {
			return
		}
		for i := 0; i < noOfFP%20; i++ {
			newPod, err := ff.GetInt()
			if err != nil {
				return
			}
			feasiblePods = append(feasiblePods, int32(newPod))
		}

		pl := &AvailabilityNodePriority{}
		pl.Score(context.Background(), args, states, feasiblePods, *key, int32(podID))
	})
}
