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
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"io"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/util/keyutil"
	envutil "k8s.io/kubectl/pkg/cmd/set/env"
	"k8s.io/kubectl/pkg/util/certificate"
	kubeadmutil "k8s.io/kubernetes/cmd/kubeadm/app/util"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
	"k8s.io/kubernetes/pkg/util/parsers"
)

// FuzzParseQuantity implements a fuzzer
// that targets resource.ParseQuantity
func FuzzParseQuantity(data []byte) int {
	_, _ = resource.ParseQuantity(string(data))
	return 1
}

// FuzzMeta1ParseToLabelSelector implements a fuzzer
// that targets metav1.ParseToLabelSelector
func FuzzMeta1ParseToLabelSelector(data []byte) int {
	_, _ = metav1.ParseToLabelSelector(string(data))
	return 1
}

// FuzzParseSelector implements a fuzzer
// that targets fields.ParseSelector
func FuzzParseSelector(data []byte) int {
	_, _ = fields.ParseSelector(string(data))
	return 1
}

// FuzzLabelsParse implements a fuzzer
// that targets labels.Parse
func FuzzLabelsParse(data []byte) int {
	_, _ = labels.Parse(string(data))
	return 1
}

// FuzzParseGroupVersion implements a fuzzer
// that targets schema.ParseGroupVersion
func FuzzParseGroupVersion(data []byte) int {
	_, _ = schema.ParseGroupVersion(string(data))
	return 1
}

// FuzzParseResourceArg implements a fuzzer
// that targets schema.ParseResourceArg
func FuzzParseResourceArg(data []byte) int {
	_, _ = schema.ParseResourceArg(string(data))
	return 1
}

// FuzzParseVersion implements a fuzzer
// that targets:
// - version.ParseSemantic,
// - version/(*Version).String()
// - version.ParseGeneric
// - version/(*Version).AtLeast(*Version)
func FuzzParseVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	vString1, err := f.GetString()
	if err != nil {
		return 0
	}
	v1, err := version.ParseSemantic(vString1)
	if err != nil {
		return 0
	}

	// Test if the Version will crash (*Version).String()
	_ = v1.String()

	vString2, err := f.GetString()
	if err != nil {
		return 0
	}
	v2, err := version.ParseGeneric(vString2)
	if err != nil {
		return 0
	}
	_ = v1.AtLeast(v2)
	return 1
}

// FuzzParsePrivateKeyPEM implements a fuzzer
// that targets keyutil.ParsePrivateKeyPEM
func FuzzParsePrivateKeyPEM(data []byte) int {
	_, _ = keyutil.ParsePrivateKeyPEM(data)
	return 1
}

// FuzzParsePublicKeysPEM implements a fuzzer
// that targets keyutil.ParsePublicKeysPEM
func FuzzParsePublicKeysPEM(data []byte) int {
	_, _ = keyutil.ParsePublicKeysPEM(data)
	return 1
}

// FuzzParseHostPort implements a fuzzer
// that targets kubeadmutil.ParseHostPort
func FuzzParseHostPort(data []byte) int {
	_, _, _ = kubeadmutil.ParseHostPort(string(data))
	return 1
}

// FuzzUrlsMatch implements a fuzzer
// that targets credentialprovider.URLsMatchStr
func FuzzUrlsMatch(data []byte) int {
	f := fuzz.NewConsumer(data)
	glob, err := f.GetString()
	if err != nil {
		return 0
	}
	target, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = credentialprovider.URLsMatchStr(glob, target)
	return 1
}

// FuzzParseCSR implements a fuzzer
// that targets certificate.ParseCSR
func FuzzParseCSR(data []byte) int {
	_, _ = certificate.ParseCSR(data)
	return 1
}

// FuzzParseEnv implements a fuzzer
// that targets envutil.ParseEnv
func FuzzParseEnv(data []byte) int {
	f := fuzz.NewConsumer(data)

	// Create a pseudo-random spec.
	// Will be used as argument to the fuzz target

	// length of slice:
	qty, err := f.GetInt()
	if err != nil {
		return 0
	}
	spec := make([]string, qty, qty)

	// fill slice with values
	for i := 0; i < qty; i++ {
		s, err := f.GetString()
		if err != nil {
			return 0
		}
		spec = append(spec, s)
	}
	var r io.Reader
	_, _, _, _ = envutil.ParseEnv(spec, r)
	return 1
}

// FuzzParseQOSReserve implements a fuzzer
// that targets cm.ParseQOSReserved
func FuzzParseQOSReserve(data []byte) int {
	f := fuzz.NewConsumer(data)

	// Create a pseudo-random map.
	// Will be used as argument to the fuzz target
	m := make(map[string]string)
	err := f.FuzzMap(&m)
	if err != nil {
		return 0
	}
	_, _ = cm.ParseQOSReserved(m)
	return 1
}

// FuzzParseCPUSet implements a fuzzer
// that targets:
// - cpuset.Parse
// - cpuset/(CPUSet).String
func FuzzParseCPUSet(data []byte) int {
	cs, err := cpuset.Parse(string(data))
	if err != nil {
		return 0
	}
	_ = cs.String()
	return 1
}

// FuzzParseImageName implements a fuzzer
// that targets parsers.ParseImageName
func FuzzParseImageName(data []byte) int {
	_, _, _, _ = parsers.ParseImageName(string(data))
	return 1
}
