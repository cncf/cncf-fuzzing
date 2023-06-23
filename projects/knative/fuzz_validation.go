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

package v1

import (
	"context"
	"fmt"
	"runtime/debug"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	eventingduckv1 "knative.dev/eventing/pkg/apis/duck/v1"
	eventingduckv1beta1 "knative.dev/eventing/pkg/apis/duck/v1"
	eventingv1 "knative.dev/eventing/pkg/apis/eventing/v1"
	eventingv1beta1 "knative.dev/eventing/pkg/apis/eventing/v1beta1"
	flowsv1 "knative.dev/eventing/pkg/apis/flows/v1"
	messagingv1 "knative.dev/eventing/pkg/apis/messaging/v1"
	sourcesv1 "knative.dev/eventing/pkg/apis/sources/v1"
	sourcesv1beta2 "knative.dev/eventing/pkg/apis/sources/v1beta2"
	autoscalingv1alpha1 "knative.dev/serving/pkg/apis/autoscaling/v1alpha1"
	servingv1alpha1 "knative.dev/serving/pkg/apis/serving/v1alpha1"
	servingv1beta1 "knative.dev/serving/pkg/apis/serving/v1beta1"
)

var (
	types = map[int]string{
		0:  "Revision",
		1:  "PodAutoscaler",
		2:  "Metric",
		3:  "Configuration",
		4:  "Route",
		5:  "Service",
		6:  "v1alpha1_DomainMapping",
		7:  "v1beta1_DomainMapping",
		8:  "flows_v1_Parallel",
		9:  "flows_v1_Sequence",
		10: "sources_v1beta2_PingSource",
		11: "sourcesv1_SinkBinding",
		12: "sourcesv1_PingSource",
		13: "sourcesv1_ApiServerSource",
		14: "sourcesv1_ContainerSource",
		15: "eventingv1beta1_EventType",
		16: "eventingv1_Broker",
		17: "eventingv1_Trigger",
		18: "messagingv1_Channel",
		19: "messagingv1_InMemoryChannel",
		20: "messagingv1_Subscription",
		21: "eventingduckv1_DeliverySpec",
		22: "eventingduckv1_DeliverySpec",
	}
)

func FuzzValidation(f *testing.F) {
	f.Fuzz(func(t *testing.T, objectBytes []byte, sr string, typeToTest int) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("fatal error: out of memory")
				debug.PrintStack()
				panic("fatal error: out of memory")

			}
		}()
		ctx := context.Background()
		ff := fuzz.NewConsumer(objectBytes)

		switch types[typeToTest%len(types)] {
		case "Revision":
			r1 := &Revision{}
			ff.GenerateStruct(r1)
			r1.Validate(ctx)
		case "PodAutoscaler":
			pas1 := &autoscalingv1alpha1.PodAutoscaler{}
			ff.GenerateStruct(pas1)
			pas1.Validate(ctx)

		case "Metric":
			m1 := &autoscalingv1alpha1.Metric{}
			ff.GenerateStruct(m1)
			m1.Validate(ctx)

		case "Configuration":
			c1 := &Configuration{}
			ff.GenerateStruct(c1)
			c1.Validate(ctx)

		case "Route":
			r1 := &Route{}
			ff.GenerateStruct(r1)
			r1.Validate(ctx)

		case "Service":
			s1 := &Service{}
			ff.GenerateStruct(s1)
			s1.Validate(ctx)

		case "v1alpha1_DomainMapping":
			dm1 := &servingv1alpha1.DomainMapping{}
			ff.GenerateStruct(dm1)
			dm1.Validate(ctx)

		case "v1beta1_DomainMapping":
			dm1 := &servingv1beta1.DomainMapping{}
			ff.GenerateStruct(dm1)
			dm1.Validate(ctx)

		case "flows_v1_Parallel":
			p1 := &flowsv1.Parallel{}
			ff.GenerateStruct(p1)
			p1.Validate(ctx)

		case "flows_v1_Sequence":
			s1 := &flowsv1.Sequence{}
			ff.GenerateStruct(s1)
			s1.Validate(ctx)

		case "sources_v1beta2_PingSource":
			p1s := &sourcesv1beta2.PingSource{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "sourcesv1_SinkBinding":
			p1s := &sourcesv1.SinkBinding{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "sourcesv1_PingSource":
			p1s := &sourcesv1.PingSource{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "sourcesv1_ApiServerSource":
			p1s := &sourcesv1.ApiServerSource{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "sourcesv1_ContainerSource":
			p1s := &sourcesv1.ContainerSource{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "eventingv1beta1_EventType":
			p1s := &eventingv1beta1.EventType{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "eventingv1_Broker":
			p1s := &eventingv1.Broker{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "eventingv1_Trigger":
			p1s := &eventingv1.Trigger{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "messagingv1_Channel":
			p1s := &messagingv1.Channel{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "messagingv1_InMemoryChannel":
			p1s := &messagingv1.InMemoryChannel{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "messagingv1_Subscription":
			p1s := &messagingv1.InMemoryChannel{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "eventingduckv1beta1_DeliverySpec":
			p1s := &eventingduckv1beta1.DeliverySpec{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)

		case "eventingduckv1_DeliverySpec":
			p1s := &eventingduckv1.DeliverySpec{}
			ff.GenerateStruct(p1s)
			p1s.Validate(ctx)
		}

	})
}
