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

package webhooks

import (
	"context"
	"testing"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
)

func FuzzWebhookValidation(f *testing.F) {
    f.Fuzz(func (t *testing.T, targetType int, data []byte){
		switch targetType % 4 {
		case 0:
			fuzzMachineValidate(data)
		case 1:
			fuzzMachineDeploymentSpecValidate(data)
		case 2:
			fuzzMachineHealthCheck(data)
		case 3:
			fuzzMachineSet(data)
		}
	})
}

func fuzzMachineValidate(data []byte) {
	fdp := fuzz.NewConsumer(data)
	m1 := &Machine{}
	err := fdp.GenerateStruct(m1)
	if err != nil {
		return
	}
	m2 := &clusterv1.Machine{}
	err = fdp.GenerateStruct(m2)
	if err != nil {
		return
	}
	_, err = m1.ValidateCreate(context.Background(), m2)
	if err != nil {
		return
	}
	m1.ValidateUpdate(context.Background(), m2, m2)
}

func fuzzMachineDeploymentSpecValidate(data []byte) {
	fdp := fuzz.NewConsumer(data)
	md1 := MachineDeployment{}
	err := fdp.GenerateStruct(&md1)
	if err != nil {
		return
	}
	md2 := &clusterv1.MachineDeployment{}
	err = fdp.GenerateStruct(md2)
	if err != nil {
		return
	}
	_, err = md1.ValidateCreate(context.Background(), md2)
	if err != nil {
		return
	}
	md1.ValidateUpdate(context.Background(), md2, md2)
}

func fuzzMachineHealthCheck(data []byte) {
	fdp := fuzz.NewConsumer(data)
	mhc1 := &MachineHealthCheck{}
	err := fdp.GenerateStruct(mhc1)
	if err != nil {
		return
	}
	mhc2 := &clusterv1.MachineHealthCheck{}
	err = fdp.GenerateStruct(mhc2)
	if err != nil {
		return
	}
	_, err = mhc1.ValidateCreate(context.Background(), mhc2)
	if err != nil {
		return
	}
	mhc1.ValidateUpdate(context.Background(), mhc2, mhc2)
}

func fuzzMachineSet(data []byte) {
	fdp := fuzz.NewConsumer(data)
	ms1 := &MachineSet{}
	err := fdp.GenerateStruct(ms1)
	if err != nil {
		return
	}
	ms2 := &clusterv1.MachineSet{}
	err = fdp.GenerateStruct(ms2)
	if err != nil {
		return
	}
	_, err = ms1.ValidateCreate(context.Background(), ms2)
	if err != nil {
		return
	}
	ms1.ValidateUpdate(context.Background(), ms2, ms2)
}
