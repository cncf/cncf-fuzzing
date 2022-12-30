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

package repository

import (
	"context"
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v2/util/git"
	"k8s.io/apimachinery/pkg/api/resource"
)

func FuzzGenerateManifests(data []byte) int {
	dir, err := os.MkdirTemp("", "fuzz-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)
	f := fuzz.NewConsumer(data)
	err = f.CreateFiles(dir)
	if err != nil {
		return 0
	}
	resString, err := f.GetString()
	if err != nil {
		return 0
	}
	res, err := resource.ParseQuantity(resString)
	if err != nil {
		return 0
	}
	src := argoappv1.ApplicationSource{Path: "manifests/base"}
	q := apiclient.ManifestRequest{Repo: &argoappv1.Repository{}, ApplicationSource: &src}
	_, _ = GenerateManifests(context.Background(), dir, "/", "", &q, false, &git.NoopCredsStore{}, res, nil)
	return 1
}
