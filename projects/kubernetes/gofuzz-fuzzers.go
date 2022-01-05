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

package fuzzing

import (
	"sync"
	"testing"

	"github.com/AdaLogics/go-fuzz-headers/bytesource"

	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	apitesting "k8s.io/kubernetes/pkg/api/testing"
	controllerFuzzer "k8s.io/kubernetes/pkg/controller/apis/config/fuzzer"
	controllerScheme "k8s.io/kubernetes/pkg/controller/apis/config/scheme"
	kubeletFuzzer "k8s.io/kubernetes/pkg/kubelet/apis/config/fuzzer"
	kubeletScheme "k8s.io/kubernetes/pkg/kubelet/apis/config/scheme"
	proxyFuzzer "k8s.io/kubernetes/pkg/proxy/apis/config/fuzzer"
	proxyScheme "k8s.io/kubernetes/pkg/proxy/apis/config/scheme"
)

var (
	initter sync.Once
)

func initForFuzzing() {
	testing.Init()
}

func FuzzRoundTripSpecificKind(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}
	internalGVK := schema.GroupVersionKind{Group: "apps", Version: runtime.APIVersionInternal, Kind: "DaemonSet"}

	seed := bytesource.New(data)
	fuzzer := fuzzer.FuzzerFor(apitesting.FuzzerFuncs, seed, legacyscheme.Codecs)

	roundtrip.RoundTripSpecificKind(t, internalGVK, legacyscheme.Scheme, legacyscheme.Codecs, fuzzer, nil)
	return 1
}

func FuzzControllerRoundtrip(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := bytesource.New(data)
	f := fuzzer.FuzzerFor(controllerFuzzer.Funcs, seed, legacyscheme.Codecs)

	codecFactory := runtimeserializer.NewCodecFactory(controllerScheme.Scheme)
	roundtrip.RoundTripTypesWithoutProtobuf(t, controllerScheme.Scheme, codecFactory, f, nil)
	return 1
}

func FuzzKubeletSchemeRoundtrip(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := bytesource.New(data)
	f := fuzzer.FuzzerFor(kubeletFuzzer.Funcs, seed, legacyscheme.Codecs)

	klScheme, _, err := kubeletScheme.NewSchemeAndCodecs()
	if err != nil {
		return 0
	}
	codecFactory := runtimeserializer.NewCodecFactory(klScheme)
	roundtrip.RoundTripTypesWithoutProtobuf(t, klScheme, codecFactory, f, nil)
	return 1
}

func FuzzProxySchemeRoundtrip(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := bytesource.New(data)
	f := fuzzer.FuzzerFor(proxyFuzzer.Funcs, seed, legacyscheme.Codecs)

	codecFactory := runtimeserializer.NewCodecFactory(proxyScheme.Scheme)
	roundtrip.RoundTripTypesWithoutProtobuf(t, proxyScheme.Scheme, codecFactory, f, nil)
	return 1
}

func FuzzRoundTripType(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := bytesource.New(data)
	f := fuzzer.FuzzerFor(apitesting.FuzzerFuncs, seed, legacyscheme.Codecs)
	nonRoundTrippableTypes := map[schema.GroupVersionKind]bool{}

	roundtrip.RoundTripTypes(t, legacyscheme.Scheme, legacyscheme.Codecs, f, nonRoundTrippableTypes)
	return 1
}
