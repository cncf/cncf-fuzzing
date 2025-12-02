// Copyright 2025 the cncf-fuzzing authors
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

package pool

import (
	"k8s.io/client-go/util/workqueue"

	"kubevirt.io/kubevirt/pkg/testutils"
)

// These utils are needed for the fuzzer
func ShutdownCtrlQueue(ctrl *Controller) {
	ctrl.queue.ShutDown()
}

func SetQueue(ctrl *Controller, newQueue *testutils.MockWorkQueue[string]) {
	ctrl.queue = newQueue
}

func GetQueue(ctrl *Controller) workqueue.TypedRateLimitingInterface[string] {
	return ctrl.queue
}
