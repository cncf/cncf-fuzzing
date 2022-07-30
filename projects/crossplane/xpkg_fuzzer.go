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

package xpkg

import (
	"bytes"
	"context"
	"io/ioutil"

	"github.com/crossplane/crossplane-runtime/pkg/parser"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/spf13/afero"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzParse(data []byte) int {
	objScheme := runtime.NewScheme()
	metaScheme := runtime.NewScheme()
	p := parser.New(metaScheme, objScheme)
	r := ioutil.NopCloser(bytes.NewReader(data))
	_, _ = p.Parse(context.Background(), r)
	return 1
}

func FuzzFindXpkgInDir(data []byte) int {
	f := fuzz.NewConsumer(data)
	noOfFiles, err := f.GetInt()
	if err != nil {
		return 0
	}
	fs := afero.NewMemMapFs()
	createdFiles := make([]string, 0)

	defer func() {
		for _, createdFile := range createdFiles {
			fs.Remove(createdFile)
		}
	}()

	for i := 0; i < noOfFiles%500; i++ {
		fname, err := f.GetString()
		if err != nil {
			return 0
		}
		fcontents, err := f.GetBytes()
		if err != nil {
			return 0
		}

		if err = afero.WriteFile(fs, fname, fcontents, 0777); err != nil {
			return 0
		}
	}

	_, _ = FindXpkgInDir(fs, "/")
	_, _ = ParseNameFromMeta(fs, "/")
	return 1
}
