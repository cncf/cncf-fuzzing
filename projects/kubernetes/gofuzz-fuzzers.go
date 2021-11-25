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
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	//fuzz "github.com/google/gofuzz"
	//"github.com/google/gofuzz/bytesource"
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
	"sync"
	"testing"
)

type ByteSource struct {
	*bytes.Reader
	fallback rand.Source
}

// New returns a new ByteSource from a given slice of bytes.
func New(input []byte) *ByteSource {
	s := &ByteSource{
		Reader:   bytes.NewReader(input),
		fallback: rand.NewSource(0),
	}
	if len(input) > 0 {
		s.fallback = rand.NewSource(int64(s.consumeUint64()))
	}
	return s
}

func (s *ByteSource) Uint64() uint64 {
	// Return from input if it was not exhausted.
	if s.Len() > 0 {
		return s.consumeUint64()
	}

	// Input was exhausted, return random number from fallback (in this case fallback should not be
	// nil). Try first having a Uint64 output (Should work in current rand implementation),
	// otherwise return a conversion of Int63.
	if s64, ok := s.fallback.(rand.Source64); ok {
		return s64.Uint64()
	}
	return uint64(s.fallback.Int63())
}

func (s *ByteSource) Int63() int64 {
	return int64(s.Uint64() >> 1)
}

func (s *ByteSource) Seed(seed int64) {
	s.fallback = rand.NewSource(seed)
	s.Reader = bytes.NewReader(nil)
}

// consumeUint64 reads 8 bytes from the input and convert them to a uint64. It assumes that the the
// bytes reader is not empty.
func (s *ByteSource) consumeUint64() uint64 {
	var bytes [8]byte
	_, err := s.Read(bytes[:])
	if err != nil && err != io.EOF {
		panic("failed reading source") // Should not happen.
	}
	return binary.BigEndian.Uint64(bytes[:])
}

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

	seed := New(data)
	fuzzer := fuzzer.FuzzerFor(apitesting.FuzzerFuncs, seed, legacyscheme.Codecs)

	roundtrip.RoundTripSpecificKind(t, internalGVK, legacyscheme.Scheme, legacyscheme.Codecs, fuzzer, nil)
	return 1
}

func FuzzControllerRoundtrip(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := New(data)
	f := fuzzer.FuzzerFor(controllerFuzzer.Funcs, seed, legacyscheme.Codecs)

	codecFactory := runtimeserializer.NewCodecFactory(controllerScheme.Scheme)
	roundtrip.RoundTripTypesWithoutProtobuf(t, controllerScheme.Scheme, codecFactory, f, nil)
	return 1
}

func FuzzKubeletSchemeRoundtrip(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := New(data)
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

	seed := New(data)
	f := fuzzer.FuzzerFor(proxyFuzzer.Funcs, seed, legacyscheme.Codecs)

	codecFactory := runtimeserializer.NewCodecFactory(proxyScheme.Scheme)
	roundtrip.RoundTripTypesWithoutProtobuf(t, proxyScheme.Scheme, codecFactory, f, nil)
	return 1
}

func FuzzRoundTripType(data []byte) int {
	initter.Do(initForFuzzing)
	t := &testing.T{}

	seed := New(data)
	f := fuzzer.FuzzerFor(apitesting.FuzzerFuncs, seed, legacyscheme.Codecs)
	nonRoundTrippableTypes := map[schema.GroupVersionKind]bool{}

	roundtrip.RoundTripTypes(t, legacyscheme.Scheme, legacyscheme.Codecs, f, nonRoundTrippableTypes)
	return 1
}
