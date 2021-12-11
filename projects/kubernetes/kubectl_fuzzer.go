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
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"path/filepath"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"sigs.k8s.io/yaml"

	"k8s.io/kubectl/pkg/apply"
	"k8s.io/kubectl/pkg/apply/parse"
	"k8s.io/kubectl/pkg/apply/strategy"
	tst "k8s.io/kubectl/pkg/util/openapi/testing"
)

var (
	downloader sync.Once
	crdURL        = "https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/kubectl/testdata/openapi/swagger.json"
	fakeResources *tst.FakeResources
)

func downloadCrd() {
	err := DownloadFile("./swagger.json", crdURL)
	if err != nil {
		panic(err)
	}
	fakeResources = tst.NewFakeResources(filepath.Join(".", "swagger.json"))
}

func DownloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func FuzzCreateElement(data []byte) int {
	downloader.Do(downloadCrd)
	f := fuzz.NewConsumer(data)
	recordedString, err := f.GetString()
	if err != nil {
		return 0
	}
	recorded, err := create(recordedString)
	if err != nil {
		return 0
	}
	localString, err := f.GetString()
	if err != nil {
		return 0
	}
	local, err := create(localString)
	if err != nil {
		return 0
	}
	remoteString, err := f.GetString()
	if err != nil {
		return 0
	}
	remote, err := create(remoteString)
	if err != nil {
		return 0
	}

	applyStrategy := strategy.Create(strategy.Options{FailOnConflict: false})

	runConflictTest(applyStrategy, recorded, local, remote)

	return 1
}

// create parses the yaml string into a map[string]interface{}.  Verifies that the string does not have
// any tab characters.
func create(config string) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	// The yaml parser will throw an obscure error if there are tabs in the yaml.  Check for this
	if strings.Contains(config, "\t") {
		return result, fmt.Errorf("String contains tabs")
	}
	err := yaml.Unmarshal([]byte(config), &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func runConflictTest(instance apply.Strategy, recorded, local, remote map[string]interface{}) {
	parseFactory := parse.Factory{Resources: fakeResources}
	parsed, err := parseFactory.CreateElement(recorded, local, remote)
	if err != nil {
		return
	}
	_, _ = parsed.Merge(instance)
}
