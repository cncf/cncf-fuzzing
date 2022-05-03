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

package sensors

import (
	"context"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	"gopkg.in/yaml.v2"
)

func FuzzgetDependencyExpression(data []byte) int {
	f := fuzz.NewConsumer(data)
	templBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	templ := &v1alpha1.TriggerTemplate{}
	err = yaml.Unmarshal(templBytes, templ)
	if err != nil {
		return 0
	}
	sensorObj := &v1alpha1.Sensor{}
	err = f.GenerateStruct(sensorObj)
	if err != nil {
		return 0
	}
	ft := &v1alpha1.Trigger{}
	if err != nil {
		return 0
	}
	ft.Template = templ
	sensorObj.Spec.Triggers = []v1alpha1.Trigger{*ft}
	sensorCtx := &SensorContext{
		sensor: sensorObj,
	}
	_, err = sensorCtx.getDependencyExpression(context.Background(), *ft)
	if err != nil {
		return 0
	}
	return 1
}
