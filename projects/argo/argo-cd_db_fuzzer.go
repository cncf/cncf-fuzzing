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

package db

import (
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v2/util/settings"
)

const (
	testNamespace = "default"
)

func FuzzCreateRepoCertificate(data []byte) int {
	f := fuzz.NewConsumer(data)
	repocertlist := &v1alpha1.RepositoryCertificateList{}
	err := f.GenerateStruct(repocertlist)
	if err != nil {
		return 0
	}
	upsert, err := f.GetBool()
	if err != nil {
		return 0
	}
	clientset := getCertClientset()
	db := NewDB(testNamespace, settings.NewSettingsManager(context.Background(), clientset, testNamespace), clientset)
	_, _ = db.CreateRepoCertificate(context.Background(), repocertlist, upsert)
	return 1
}
