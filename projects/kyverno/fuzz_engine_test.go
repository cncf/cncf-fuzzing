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

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	kyverno "github.com/kyverno/kyverno/api/kyverno/v1"
	kyvernov1beta1 "github.com/kyverno/kyverno/api/kyverno/v1beta1"
	client "github.com/kyverno/kyverno/pkg/clients/dclient"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/adapters"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/factories"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/engine/policycontext"
	"github.com/kyverno/kyverno/pkg/registryclient"
	kubeutils "github.com/kyverno/kyverno/pkg/utils/kube"
)

/*
	VerifyAndPatchImage
*/

var (
	fuzzCfg        = config.NewDefaultConfiguration(false)
	fuzzMetricsCfg = config.NewDefaultMetricsConfiguration()
	fuzzJp         = jmespath.New(fuzzCfg)
)

func buildFuzzContext(policy, resource, oldResource []byte) (*PolicyContext, error) {
	var cpol kyverno.ClusterPolicy
	err := json.Unmarshal([]byte(policy), &cpol)
	if err != nil {
		return nil, err
	}

	resourceUnstructured, err := kubeutils.BytesToUnstructured(resource)
	if err != nil {
		return nil, err
	}

	policyContext, err := policycontext.NewPolicyContext(
		fuzzJp,
		*resourceUnstructured,
		kyverno.Create,
		nil,
		fuzzCfg,
	)
	if err != nil {
		return nil, err
	}

	policyContext = policyContext.
		WithPolicy(&cpol).
		WithNewResource(*resourceUnstructured)

	if !bytes.Equal(oldResource, []byte("")) {
		oldResourceUnstructured, err := kubeutils.BytesToUnstructured(oldResource)
		if err != nil {
			return nil, err
		}

		err = enginecontext.AddOldResource(policyContext.JSONContext(), oldResource)
		if err != nil {
			return nil, err
		}

		policyContext = policyContext.WithOldResource(*oldResourceUnstructured)
	}

	return policyContext, nil
}

func testFuzzVerifyAndPatchImages(
	ctx context.Context,
	rclient registryclient.Client,
	cmResolver engineapi.ConfigmapResolver,
	pContext engineapi.PolicyContext,
	cfg config.Configuration,
) (engineapi.EngineResponse, engineapi.ImageVerificationMetadata) {
	e := NewEngine(
		cfg,
		fuzzMetricsCfg,
		fuzzJp,
		nil,
		factories.DefaultRegistryClientFactory(adapters.RegistryClient(rclient), nil),
		factories.DefaultContextLoaderFactory(cmResolver),
		nil,
		"",
	)
	return e.VerifyAndPatchImages(
		ctx,
		pContext,
	)
}

func FuzzVerifyImageAndPatchTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, policy, resource, oldResource []byte) {
		pc, err := buildFuzzContext(policy, resource, oldResource)
		if err != nil {
			return
		}
		_ = pc
		engineResp, _ := testFuzzVerifyAndPatchImages(context.Background(), registryclient.NewOrDie(), nil, pc, fuzzCfg)
		_ = engineResp
	})
}

/*
	Vaidate
*/

func newFuzzPolicyContext(
	resource unstructured.Unstructured,
	operation kyverno.AdmissionOperation,
	admissionInfo *kyvernov1beta1.RequestInfo,
) (*PolicyContext, error) {
	p, err := NewPolicyContext(fuzzJp, resource, operation, admissionInfo, fuzzCfg)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func testValidateFuzz(
	ctx context.Context,
	rclient registryclient.Client,
	pContext *PolicyContext,
	cfg config.Configuration,
	contextLoader engineapi.ContextLoaderFactory,
) engineapi.EngineResponse {
	if contextLoader == nil {
		contextLoader = factories.DefaultContextLoaderFactory(nil)
	}
	e := NewEngine(
		cfg,
		config.NewDefaultMetricsConfiguration(),
		fuzzJp,
		nil,
		factories.DefaultRegistryClientFactory(adapters.RegistryClient(rclient), nil),
		contextLoader,
		nil,
		"",
	)
	return e.Validate(
		ctx,
		pContext,
	)
}

func FuzzEngineValidateTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, rawResource, rawPolicy []byte) {
		var policy kyverno.ClusterPolicy
		err := json.Unmarshal(rawPolicy, &policy)
		if err != nil {
			return
		}

		resourceUnstructured, err := kubeutils.BytesToUnstructured(rawResource)
		if err != nil {
			return
		}

		pc, err := newFuzzPolicyContext(*resourceUnstructured, kyverno.Create, nil)
		if err != nil {
			return
		}
		testValidateFuzz(context.Background(), registryclient.NewOrDie(), pc.WithPolicy(&policy), fuzzCfg, nil)

	})
}

/*
	Mutate
*/

func createMutateContext(policy kyverno.PolicyInterface, resource unstructured.Unstructured, operation kyverno.AdmissionOperation) (*PolicyContext, error) {
	ctx, err := NewPolicyContext(
		fuzzJp,
		resource,
		kyverno.Create,
		nil,
		fuzzCfg,
	)
	if err != nil {
		return nil, err
	}
	return ctx.WithPolicy(policy), nil
}

func testMutateFuzz(
	ctx context.Context,
	client client.Interface,
	rclient registryclient.Client,
	pContext *PolicyContext,
	contextLoader engineapi.ContextLoaderFactory,
) engineapi.EngineResponse {
	if contextLoader == nil {
		contextLoader = factories.DefaultContextLoaderFactory(nil)
	}
	e := NewEngine(
		fuzzCfg,
		config.NewDefaultMetricsConfiguration(),
		fuzzJp,
		adapters.Client(client),
		factories.DefaultRegistryClientFactory(adapters.RegistryClient(rclient), nil),
		contextLoader,
		nil,
		"",
	)
	return e.Mutate(
		ctx,
		pContext,
	)
}

func FuzzMutateTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, resourceRaw, policyRaw []byte) {
		var policy kyverno.ClusterPolicy
		err := json.Unmarshal(policyRaw, &policy)
		if err != nil {
			return
		}
		var resource unstructured.Unstructured
		err = resource.UnmarshalJSON(resourceRaw)
		if err != nil {
			return
		}

		pc, err := createMutateContext(&policy, resource, kyverno.Create)
		if err != nil {
			return
		}
		testMutateFuzz(context.Background(), nil, nil, pc, nil)
	})
}

