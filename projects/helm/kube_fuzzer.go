// Copyright 2022 ADA Logics Ltd
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

package kube

import (
	"bytes"
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"io"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest/fake"
	cmdtesting "k8s.io/kubectl/pkg/cmd/testing"
	"net/http"
	"testing"
)

var fuzzCodec = scheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)

func createPod(f *fuzz.ConsumeFuzzer) (v1.Pod, error) {
	pod := v1.Pod{}
	err := f.GenerateStruct(&pod)
	if err != nil {
		return pod, err
	}
	return pod, nil
}

func createPodList(f *fuzz.ConsumeFuzzer) (v1.PodList, error) {
	var list v1.PodList
	noOfPods, err := f.GetInt()
	if err != nil {
		return list, err
	}
	for i := 0; i < noOfPods%20; i++ {
		newPod, err := createPod(f)
		if err != nil {
			return list, err
		}
		list.Items = append(list.Items, newPod)
	}
	return list, nil
}

func objBodyFuzz(obj runtime.Object) (io.ReadCloser, error) {
	bodyBytes, err := runtime.Encode(fuzzCodec, obj)
	if err != nil {
		return nil, err
	}
	return ioutil.NopCloser(bytes.NewReader([]byte(bodyBytes))), nil
}

func newResponseFuzz(code int, obj runtime.Object) (*http.Response, error) {
	header := http.Header{}
	header.Set("Content-Type", runtime.ContentTypeJSON)
	objBody, err := runtime.Encode(codec, obj)
	if err != nil {
		return &http.Response{}, err
	}
	body := ioutil.NopCloser(bytes.NewReader([]byte(objBody)))
	return &http.Response{StatusCode: code, Header: header, Body: body}, nil
}

func FuzzKubeClient(data []byte) int {
	f := fuzz.NewConsumer(data)
	listA, err := createPodList(f)
	if err != nil {
		return 0
	}
	objBodyA, err := objBodyFuzz(&listA)
	if err != nil {
		return 0
	}
	listB, err := createPodList(f)
	if err != nil {
		return 0
	}
	objBodyB, err := objBodyFuzz(&listB)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	c := newTestClient(t)
	var actions []string

	c.Factory.(*cmdtesting.TestFactory).UnstructuredClient = &fake.RESTClient{
		NegotiatedSerializer: unstructuredSerializer,
		Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			p, m := req.URL.Path, req.Method
			actions = append(actions, p+":"+m)
			switch {
			case p == "/namespaces/default/pods/starfish" && m == "GET":
				return newResponseFuzz(200, &listA.Items[0])
			case p == "/namespaces/default/pods/otter" && m == "GET":
				return newResponseFuzz(200, &listA.Items[1])
			case p == "/namespaces/default/pods/otter" && m == "PATCH":
				_, err := ioutil.ReadAll(req.Body)
				if err != nil {
					panic(fmt.Sprintf("could not dump request: %s\n", err))
				}
				req.Body.Close()
				return newResponseFuzz(200, &listB.Items[0])
			case p == "/namespaces/default/pods/dolphin" && m == "GET":
				return newResponseFuzz(404, notFoundBody())
			case p == "/namespaces/default/pods/starfish" && m == "PATCH":
				_, err := ioutil.ReadAll(req.Body)
				if err != nil {
					panic(fmt.Sprintf("could not dump request: %s", err))
				}
				req.Body.Close()
				return newResponseFuzz(200, &listB.Items[0])
			case p == "/namespaces/default/pods" && m == "POST":
				return newResponseFuzz(200, &listB.Items[1])
			case p == "/namespaces/default/pods/squid" && m == "DELETE":
				return newResponseFuzz(200, &listB.Items[1])
			case p == "/namespaces/default/pods/squid" && m == "GET":
				return newResponseFuzz(200, &listB.Items[2])
			default:
				return &http.Response{}, fmt.Errorf("err")
			}
		}),
	}

	first, err := c.Build(objBodyA, false)
	if err != nil {
		return 0
	}
	second, err := c.Build(objBodyB, false)
	if err != nil {
		return 0
	}
	_, _ = c.Update(first, second, false)
	return 1
}
