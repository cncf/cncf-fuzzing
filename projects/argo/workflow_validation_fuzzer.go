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

package validate

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	fakewfclientset "github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/fake"
	"github.com/argoproj/argo-workflows/v3/workflow/templateresolution"
)

var (
	wfClientsetFuzz   = fakewfclientset.NewSimpleClientset()
	wftmplGetterFuzz  = templateresolution.WrapWorkflowTemplateInterface(wfClientsetFuzz.ArgoprojV1alpha1().WorkflowTemplates(metav1.NamespaceDefault))
	cwftmplGetterFuzz = templateresolution.WrapClusterWorkflowTemplateInterface(wfClientsetFuzz.ArgoprojV1alpha1().ClusterWorkflowTemplates())
)

func FuzzValidateWorkflow(data []byte) int {
	f := fuzz.NewConsumer(data)
	wf := &wfv1.Workflow{}
	err := f.GenerateStruct(wf)
	if err != nil {
		return 0
	}
	if wf.Spec.WorkflowTemplateRef == nil {
		return 0
	}
	opts := ValidateOpts{}
	_ = ValidateWorkflow(wftmplGetterFuzz, cwftmplGetterFuzz, wf, opts)
	return 1
}
