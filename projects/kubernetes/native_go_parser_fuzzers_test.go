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

package fuzzing

import (
	"fmt"
	"io"
	"reflect"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

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
	"k8s.io/utils/cpuset"
	"k8s.io/kubernetes/pkg/util/parsers"

	"github.com/google/go-cmp/cmp"
)

// FuzzParseQuantity implements a fuzzer
// that targets resource.ParseQuantity
func FuzzParseQuantity(f *testing.F) {
	f.Fuzz(func(t *testing.T, data, data2 string) {
		q, err := resource.ParseQuantity(data)
		if err != nil {
			return
		}
		qcopy := q.DeepCopy()
		if !reflect.DeepEqual(q, qcopy) {
			panic("q and qcopy are not equal")
		}
		_ = q.String()
		qBytes, err := q.MarshalJSON()
		if err != nil {
			return
		}
		newQ := &resource.Quantity{}
		err = newQ.UnmarshalJSON(qBytes)
		if err != nil {
			panic("This should not happen")
		}
		q2 := q.DeepCopy()
		if !reflect.DeepEqual(q, q2) {
			panic(fmt.Sprintf("%+v\n", cmp.Diff(q, q2)))
		}
		_ = q.ToDec()
		_ = q.AsDec()
		_ = q.AsApproximateFloat64()
		_ = q.IsZero()
		_ = q.Sign()
		q3, err := resource.ParseQuantity(data2)
		if err != nil {
			return
		}
		q.Add(q3)
	})
}

// FuzzMeta1ParseToLabelSelector implements a fuzzer
// that targets metav1.ParseToLabelSelector
func FuzzMeta1ParseToLabelSelector(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = metav1.ParseToLabelSelector(data)
	})
}

// FuzzParseSelector implements a fuzzer
// that targets fields.ParseSelector
func FuzzParseSelector(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = fields.ParseSelector(data)
	})
}

// FuzzLabelsParse implements a fuzzer
// that targets labels.Parse
func FuzzLabelsParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = labels.Parse(data)
	})
}

// FuzzParseGroupVersion implements a fuzzer
// that targets schema.ParseGroupVersion
func FuzzParseGroupVersion(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = schema.ParseGroupVersion(data)
	})
}

// FuzzParseResourceArg implements a fuzzer
// that targets schema.ParseResourceArg
func FuzzParseResourceArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = schema.ParseResourceArg(data)
	})
}

// FuzzParseVersion implements a fuzzer
// that targets:
// - version.ParseSemantic,
// - version/(*Version).String()
// - version.ParseGeneric
// - version/(*Version).AtLeast(*Version)
func FuzzParseVersion(f *testing.F) {
	f.Fuzz(func(t *testing.T, vString1, vString2 string) {

		v1, err := version.ParseSemantic(vString1)
		if err != nil {
			return
		}

		// Test if the Version will crash (*Version).String()
		_ = v1.String()

		v2, err := version.ParseGeneric(vString2)
		if err != nil {
			return
		}
		_ = v1.AtLeast(v2)
	})
}

// FuzzParsePrivateKeyPEM implements a fuzzer
// that targets keyutil.ParsePrivateKeyPEM
func FuzzParsePrivateKeyPEM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = keyutil.ParsePrivateKeyPEM(data)
	})
}

// FuzzParsePublicKeysPEM implements a fuzzer
// that targets keyutil.ParsePublicKeysPEM
func FuzzParsePublicKeysPEM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = keyutil.ParsePublicKeysPEM(data)
	})
}

// FuzzParseHostPort implements a fuzzer
// that targets kubeadmutil.ParseHostPort
func FuzzParseHostPort(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _, _ = kubeadmutil.ParseHostPort(data)
	})
}

// FuzzUrlsMatch implements a fuzzer
// that targets credentialprovider.URLsMatchStr
func FuzzUrlsMatch(f *testing.F) {
	f.Fuzz(func(t *testing.T, glob, target string) {
		_, _ = credentialprovider.URLsMatchStr(glob, target)
	})
}

// FuzzParseCSR implements a fuzzer
// that targets certificate.ParseCSR
func FuzzParseCSR(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = certificate.ParseCSR(data)
	})
}

// FuzzParseEnv implements a fuzzer
// that targets envutil.ParseEnv
func FuzzParseEnv(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := fuzz.NewConsumer(data)

		// Create a pseudo-random spec.
		// Will be used as argument to the fuzz target

		// length of slice:
		qty, err := f.GetInt()
		if err != nil {
			return
		}
		spec := make([]string, qty, qty)

		// fill slice with values
		for i := 0; i < qty; i++ {
			s, err := f.GetString()
			if err != nil {
				return
			}
			spec = append(spec, s)
		}
		var r io.Reader
		_, _, _, _ = envutil.ParseEnv(spec, r)
	})
}

// FuzzParseQOSReserve implements a fuzzer
// that targets cm.ParseQOSReserved
func FuzzParseQOSReserve(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := fuzz.NewConsumer(data)

		// Create a pseudo-random map.
		// Will be used as argument to the fuzz target
		m := make(map[string]string)
		err := f.FuzzMap(&m)
		if err != nil {
			return
		}
		_, _ = cm.ParseQOSReserved(m)
	})
}

// FuzzParseCPUSet implements a fuzzer
// that targets:
// - cpuset.Parse
// - cpuset/(CPUSet).String
func FuzzParseCPUSet(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		cs, err := cpuset.Parse(data)
		if err != nil {
			return
		}
		_ = cs.String()
	})
}

// FuzzParseImageName implements a fuzzer
// that targets parsers.ParseImageName
func FuzzParseImageName(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_, _, _, _ = parsers.ParseImageName(data)
	})
}
