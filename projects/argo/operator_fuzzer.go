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

package controller

import (
	"context"
	"fmt"
	goruntime "runtime"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/scheme"
)

// TODO: catchOperatorPanics will be obsolete if validateWorkflowForClient
// is proven to avoid panics from fake.NewSimpleDynamicClient().
// See validateWorkflowForClient() below.
func catchOperatorPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case goruntime.Error:
			err = r.(goruntime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "failed to convert to unstructured: error decoding from json: empty value") {
			return
		} else if strings.Contains(err, "failed to convert to unstructured: error decoding number from json") {
			return
		} else if strings.Contains(err, "error calling MarshalJSON for type *v1alpha1.Item: invalid character") {
			return
		} else if strings.Contains(err, "error calling MarshalJSON for type *v1alpha1.Item: unexpected end of JSON input") {
			return
		} else if strings.Contains(err, "failed to convert to unstructured: json: error calling MarshalJSON for type *v1alpha1.Plugin: unexpected end of JSON input") {
			return
		} else {
			panic(err)
		}
	}
}

// validateWorkflowForClient performs the same checks as NewSimpleDynamicClient:
// https://github.com/kubernetes/client-go/blob/master/dynamic/fake/simple.go#L37
// but instead of panicking it exits gracefully.
// The idea here is to perform identical checks to avoid panicking when we
// finally create the client via fake.NewSimpleDynamicClient()
func validateWorkflowForClient(wf *wfv1.Workflow) bool {
	var objects []runtime.Object
	objects = append(objects, wf)

	s := scheme.Scheme

	unstructuredScheme := runtime.NewScheme()
	for gvk := range s.AllKnownTypes() {
		if unstructuredScheme.Recognizes(gvk) {
			continue
		}
		if strings.HasSuffix(gvk.Kind, "List") {
			unstructuredScheme.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
			continue
		}
		unstructuredScheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	}

	_, err := convertObjectsToUnstructured(s, objects)
	if err != nil {
		return false
	}
	return true
}

// Taken from https://github.com/kubernetes/client-go/blob/master/dynamic/fake/simple.go#L457
// to support validateWorkflowForClient
func convertObjectsToUnstructured(s *runtime.Scheme, objs []runtime.Object) ([]runtime.Object, error) {
	ul := make([]runtime.Object, 0, len(objs))

	for _, obj := range objs {
		u, err := convertToUnstructured(s, obj)
		if err != nil {
			return nil, err
		}

		ul = append(ul, u)
	}
	return ul, nil
}

// Taken from https://github.com/kubernetes/client-go/blob/master/dynamic/fake/simple.go#L471
// to support validateWorkflowForClient
func convertToUnstructured(s *runtime.Scheme, obj runtime.Object) (runtime.Object, error) {
	var (
		err error
		u   unstructured.Unstructured
	)

	u.Object, err = runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to unstructured: %w", err)
	}

	gvk := u.GroupVersionKind()
	if gvk.Group == "" || gvk.Kind == "" {
		gvks, _, err := s.ObjectKinds(obj)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to unstructured - unable to get GVK %w", err)
		}
		apiv, k := gvks[0].ToAPIVersionAndKind()
		u.SetAPIVersion(apiv)
		u.SetKind(k)
	}
	return &u, nil
}

func FuzzOperator(data []byte) int {
	f := fuzz.NewConsumer(data)
	wf := &wfv1.Workflow{}
	err := f.GenerateStruct(wf)
	if err != nil {
		return 0
	}
	if !validateWorkflowForClient(wf) {
		return 0
	}
	defer catchOperatorPanics()
	cancel, controller := newController(wf)
	defer cancel()
	ctx := context.Background()
	woc := newWorkflowOperationCtx(wf, controller)
	woc.operate(ctx)
	return 1
}
