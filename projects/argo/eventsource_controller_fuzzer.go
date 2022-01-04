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

package eventsource

import (
	"context"
	"sync"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/argoproj/argo-events/common/logging"
        eventbusv1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventbus/v1alpha1"
	"github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
)

var initter sync.Once

func initScheme() {
	_ = v1alpha1.AddToScheme(scheme.Scheme)
        _ = eventbusv1alpha1.AddToScheme(scheme.Scheme)
        _ = appv1.AddToScheme(scheme.Scheme)
        _ = corev1.AddToScheme(scheme.Scheme)
}

func FuzzEventsourceReconciler(data []byte) int {
	initter.Do(initScheme)
	f := fuzz.NewConsumer(data)
	testEventSource := &v1alpha1.EventSource{}
	err := f.GenerateStruct(testEventSource)
	if err != nil {
		return 0
	}
	cl := fake.NewClientBuilder().Build()
	testStreamingImage := "test-steaming-image"
	r := &reconciler{
		client:           cl,
		scheme:           scheme.Scheme,
		eventSourceImage: testStreamingImage,
		logger:           logging.NewArgoEventsLogger(),
	}
	ctx := context.Background()
	_ = r.reconcile(ctx, testEventSource)
	return 1
}

func FuzzResourceReconcile(data []byte) int {
        testImage := "test-image"
        initter.Do(initScheme)
        f := fuzz.NewConsumer(data)
        testEventSource := &v1alpha1.EventSource{}
        err := f.GenerateStruct(testEventSource)
        if err != nil {
                return 0
        }
        testLabels := make(map[string]string)
        err = f.FuzzMap(&testLabels)
        if err != nil {
                return 0
        }
        testBus := &eventbusv1alpha1.EventBus{}
        err = f.GenerateStruct(testBus)
        if err != nil {
                return 0
        }
        cl := fake.NewClientBuilder().Build()
        err = cl.Create(context.Background(), testBus)
        if err != nil {
                return 0
        }
        args := &AdaptorArgs{
                        Image:       testImage,
                        EventSource: testEventSource,
                        Labels:      testLabels,
                }
        _ = Reconcile(cl, args, logging.NewArgoEventsLogger())
        return 1
}