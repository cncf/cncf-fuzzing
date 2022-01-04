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

package eventbus

import (
	"context"
	"sync"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/argoproj/argo-events/common/logging"
	"github.com/argoproj/argo-events/pkg/apis/eventbus/v1alpha1"
)

var initter sync.Once

func initScheme() {
	_ = v1alpha1.AddToScheme(scheme.Scheme)
	_ = appv1.AddToScheme(scheme.Scheme)
	_ = corev1.AddToScheme(scheme.Scheme)
}

func FuzzEventbusReconciler(data []byte) int {
	initter.Do(initScheme)
	f := fuzz.NewConsumer(data)
	nativeBus := &v1alpha1.EventBus{}
	err := f.GenerateStruct(nativeBus)
	if err != nil {
		return 0
	}
	cl := fake.NewClientBuilder().Build()
	testStreamingImage := "test-steaming-image"
	r := &reconciler{
		client:             cl,
		scheme:             scheme.Scheme,
		natsStreamingImage: testStreamingImage,
		logger:             logging.NewArgoEventsLogger(),
	}
	ctx := context.Background()
	_ = r.reconcile(ctx, nativeBus)
	_ = r.needsUpdate(nativeBus, nativeBus)
	return 1
}
