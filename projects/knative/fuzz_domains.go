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

package domains

import (
	"context"
	"knative.dev/serving/pkg/apis/serving"
	"knative.dev/serving/pkg/reconciler/route/config"
	"testing"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netapi "knative.dev/networking/pkg/apis/networking"
)

func FuzzDomainNameFromTemplate(f *testing.F) {
	f.Fuzz(func(t *testing.T, template, name string, configData, objectMetaData []byte) {
		cfg := &config.Config{}
		ff := fuzz.NewConsumer(configData)
		ff.GenerateStruct(cfg)
		if cfg.Network == nil {
			t.Skip()
		}
		if cfg.Network.DomainTemplate == "" {
			t.Skip()
		}
		meta := metav1.ObjectMeta{}
		ff.GenerateStruct(&meta)
		if meta.Labels == nil {
			t.Skip()
		}
		ctx := context.Background()
		ctx = config.ToContext(ctx, cfg)

		meta.Labels[netapi.VisibilityLabelKey] = serving.VisibilityClusterLocal

		_, _ = DomainNameFromTemplate(ctx, meta, name)
	})
}
