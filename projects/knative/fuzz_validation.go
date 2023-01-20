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
	"knative.dev/pkg/apis"
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
		ff := fuzz.NewConsumer(objectBytes)

		switch types[typeToTest%len(types)] {
		case "Revision":
			r1 := &Revision{}
			ff.GenerateStruct(r1)
			r2 := &Revision{}
			ff.GenerateStruct(r2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, r2, sr)
			r1.Validate(ctx)
		case "PodAutoscaler":
			pas1 := &autoscalingv1alpha1.PodAutoscaler{}
			ff.GenerateStruct(pas1)
			pas2 := &autoscalingv1alpha1.PodAutoscaler{}
			ff.GenerateStruct(pas2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, pas2, sr)
			pas1.Validate(ctx)

		case "Metric":
			m1 := &autoscalingv1alpha1.Metric{}
			ff.GenerateStruct(m1)
			m2 := &autoscalingv1alpha1.Metric{}
			ff.GenerateStruct(m2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, m2, sr)
			m1.Validate(ctx)

		case "Configuration":
			c1 := &Configuration{}
			ff.GenerateStruct(c1)
			c2 := &Configuration{}
			ff.GenerateStruct(c2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, c2, sr)
			c1.Validate(ctx)

		case "Route":
			r1 := &Route{}
			ff.GenerateStruct(r1)
			r2 := &Route{}
			ff.GenerateStruct(r2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, r2, sr)
			r1.Validate(ctx)

		case "Service":
			s1 := &Service{}
			ff.GenerateStruct(s1)
			s2 := &Service{}
			ff.GenerateStruct(s2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, s2, sr)
			s1.Validate(ctx)

		case "v1alpha1_DomainMapping":
			dm1 := &servingv1alpha1.DomainMapping{}
			ff.GenerateStruct(dm1)
			dm2 := &servingv1alpha1.DomainMapping{}
			ff.GenerateStruct(dm2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, dm2, sr)
			dm1.Validate(ctx)

		case "v1beta1_DomainMapping":
			dm1 := &servingv1beta1.DomainMapping{}
			ff.GenerateStruct(dm1)
			dm2 := &servingv1beta1.DomainMapping{}
			ff.GenerateStruct(dm2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, dm2, sr)
			dm1.Validate(ctx)

		case "flows_v1_Parallel":
			p1 := &flowsv1.Parallel{}
			ff.GenerateStruct(p1)
			p2 := &flowsv1.Parallel{}
			ff.GenerateStruct(p2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, p2, sr)
			p1.Validate(ctx)

		case "flows_v1_Sequence":
			s1 := &flowsv1.Sequence{}
			ff.GenerateStruct(s1)
			s2 := &flowsv1.Sequence{}
			ff.GenerateStruct(s2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, s2, sr)
			s1.Validate(ctx)

		case "sources_v1beta2_PingSource":
			p1s := &sourcesv1beta2.PingSource{}
			ff.GenerateStruct(p1s)
			ps2 := &sourcesv1beta2.PingSource{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "sourcesv1_SinkBinding":
			p1s := &sourcesv1.SinkBinding{}
			ff.GenerateStruct(p1s)
			ps2 := &sourcesv1.SinkBinding{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "sourcesv1_PingSource":
			p1s := &sourcesv1.PingSource{}
			ff.GenerateStruct(p1s)
			ps2 := &sourcesv1.PingSource{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "sourcesv1_ApiServerSource":
			p1s := &sourcesv1.ApiServerSource{}
			ff.GenerateStruct(p1s)
			ps2 := &sourcesv1.ApiServerSource{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "sourcesv1_ContainerSource":
			p1s := &sourcesv1.ContainerSource{}
			ff.GenerateStruct(p1s)
			ps2 := &sourcesv1.ContainerSource{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "eventingv1beta1_EventType":
			p1s := &eventingv1beta1.EventType{}
			ff.GenerateStruct(p1s)
			ps2 := &eventingv1beta1.EventType{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "eventingv1_Broker":
			p1s := &eventingv1.Broker{}
			ff.GenerateStruct(p1s)
			ps2 := &eventingv1.Broker{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "eventingv1_Trigger":
			p1s := &eventingv1.Trigger{}
			ff.GenerateStruct(p1s)
			ps2 := &eventingv1.Trigger{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "messagingv1_Channel":
			p1s := &messagingv1.Channel{}
			ff.GenerateStruct(p1s)
			ps2 := &messagingv1.Channel{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "messagingv1_InMemoryChannel":
			p1s := &messagingv1.InMemoryChannel{}
			ff.GenerateStruct(p1s)
			ps2 := &messagingv1.InMemoryChannel{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "messagingv1_Subscription":
			p1s := &messagingv1.InMemoryChannel{}
			ff.GenerateStruct(p1s)
			ps2 := &messagingv1.InMemoryChannel{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "eventingduckv1beta1_DeliverySpec":
			p1s := &eventingduckv1beta1.DeliverySpec{}
			ff.GenerateStruct(p1s)
			ps2 := &eventingduckv1beta1.DeliverySpec{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)

		case "eventingduckv1_DeliverySpec":
			p1s := &eventingduckv1.DeliverySpec{}
			ff.GenerateStruct(p1s)
			ps2 := &eventingduckv1.DeliverySpec{}
			ff.GenerateStruct(ps2)
			ctxBackground := context.Background()
			ctx := apis.WithinSubResourceUpdate(ctxBackground, ps2, sr)
			p1s.Validate(ctx)
		}

	})
}
