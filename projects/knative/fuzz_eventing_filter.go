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

package filter

import (
	"context"
	"testing"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	eventingv1 "knative.dev/eventing/pkg/apis/eventing/v1"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)



func FuzzFilters(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, apiCall int) {
		ff := fuzz.NewConsumer(data)
		event := &cloudevents.Event{}
		ff.GenerateStruct(event)
		ctx := context.Background()
		switch apiCall%2 {
		case 0:
			filters := make([]eventingv1.SubscriptionsAPIFilter, 0)
			noOfFilters, err := ff.GetInt()
			if err != nil {
				t.Skip()
			}
			if noOfFilters == 0 {
				noOfFilters = 1
			}
			for i:=0;i<10%noOfFilters;i++ {
				filt := &eventingv1.SubscriptionsAPIFilter{}
				ff.GenerateStruct(filt)
				filters = append(filters, *filt)
			}
			_ = applySubscriptionsAPIFilters(ctx, filters, *event)
		case 1:
			filter := &eventingv1.TriggerFilter{}
			ff.GenerateStruct(filter)
			_ = applyAttributesFilter(ctx, filter, *event)
		}
	})
}