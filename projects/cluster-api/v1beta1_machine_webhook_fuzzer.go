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

package v1beta1

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzWebhookValidation(data []byte) int {
	if len(data) < 10 {
		return -1
	}
	targetType := int(data[0])
	restOfData := data[1:]
	switch targetType % 4 {
	case 0:
		return fuzzMachineValidate(restOfData)
	case 1:
		return fuzzMachineDeploymentSpecValidate(restOfData)
	case 2:
		return fuzzMachineHealthCheck(restOfData)
	case 3:
		return fuzzMachineSet(restOfData)
	}
	return 1
}

func fuzzMachineValidate(data []byte) int {
	f := fuzz.NewConsumer(data)
	m1 := &Machine{}
	err := f.GenerateStruct(m1)
	if err != nil {
		return 0
	}
	err = m1.ValidateCreate()
	if err != nil {
		return 0
	}
	m2 := &Machine{}
	err = f.GenerateStruct(m2)
	if err != nil {
		return 0
	}
	m1.ValidateUpdate(m2)
	return 1
}

func fuzzMachineDeploymentSpecValidate(data []byte) int {
	f := fuzz.NewConsumer(data)
	md1 := &MachineDeployment{}
	err := f.GenerateStruct(md1)
	if err != nil {
		return 0
	}
	err = md1.ValidateCreate()
	if err != nil {
		return 0
	}
	md2 := &MachineDeployment{}
	err = f.GenerateStruct(md2)
	if err != nil {
		return 0
	}
	md1.ValidateUpdate(md2)
	return 1
}

func fuzzMachineHealthCheck(data []byte) int {
	f := fuzz.NewConsumer(data)
	mhc1 := &MachineHealthCheck{}
	err := f.GenerateStruct(mhc1)
	if err != nil {
		return 0
	}
	err = mhc1.ValidateCreate()
	if err != nil {
		return 0
	}
	mhc2 := &MachineHealthCheck{}
	err = f.GenerateStruct(mhc2)
	if err != nil {
		return 0
	}
	mhc1.ValidateUpdate(mhc2)
	return 1
}

func fuzzMachineSet(data []byte) int {
	f := fuzz.NewConsumer(data)
	ms1 := &MachineSet{}
	err := f.GenerateStruct(ms1)
	if err != nil {
		return 0
	}
	err = ms1.ValidateCreate()
	if err != nil {
		return 0
	}
	ms2 := &MachineSet{}
	err = f.GenerateStruct(ms2)
	if err != nil {
		return 0
	}
	ms1.ValidateUpdate(ms2)
	return 1
}
