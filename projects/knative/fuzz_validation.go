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

	"knative.dev/pkg/apis"
	autoscalingv1alpha1 "knative.dev/serving/pkg/apis/autoscaling/v1alpha1"
	servingv1alpha1 "knative.dev/serving/pkg/apis/serving/v1alpha1"
	servingv1beta1 "knative.dev/serving/pkg/apis/serving/v1beta1"
)

var (
	types = map[int]string{
		0: "Revision",
		1: "PodAutoscaler",
		2: "Metric",
		3: "Configuration",
		4: "Route",
		5: "Service",
		6: "v1alpha1_DomainMapping",
		7: "v1beta1_DomainMapping",
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

		}

	})
}
