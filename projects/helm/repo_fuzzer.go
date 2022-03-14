//go:build gofuzz
// +build gofuzz

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

package repo

import (
	"bufio"
	"bytes"
	"fmt"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/helmpath"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"helm.sh/helm/v3/pkg/chart"
)

func FuzzIndex(data []byte) int {
	f := fuzz.NewConsumer(data)
	indexFileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	md := &chart.Metadata{}
	err = f.GenerateStruct(md)
	if err != nil {
		return 0
	}
	filename, err := f.GetString()
	if err != nil {
		return 0
	}
	baseURL, err := f.GetString()
	if err != nil {
		return 0
	}
	name, err := f.GetString()
	if err != nil {
		return 0
	}
	version, err := f.GetString()
	if err != nil {
		return 0
	}
	digest, err := f.GetString()
	if err != nil {
		return 0
	}
	indf, err := os.Create("indexfile")
	if err != nil {
		return 0
	}
	defer indf.Close()
	defer os.Remove("indexfile")
	_, err = indf.Write(indexFileBytes)
	if err != nil {
		return 0
	}
	ind, err := LoadIndexFile("indexfile")
	if err != nil {
		return 0
	}
	ind.MustAdd(md, filename, baseURL, digest)
	ind.Get(name, version)
	return 1
}

func FuzzWriteFile(data []byte) int {
	f := fuzz.NewConsumer(data)
	fileContents, err := f.GetBytes()
	if err != nil {
		return 0
	}
	md := &chart.Metadata{}
	err = f.GenerateStruct(md)
	if err != nil {
		return 0
	}
	baseURL, err := f.GetString()
	if err != nil {
		return 0
	}
	digest, err := f.GetString()
	if err != nil {
		return 0
	}
	repeatBytesTimes, err := f.GetInt()
	if err != nil {
		return 0
	}
	fileContents = bytes.Repeat(fileContents, repeatBytesTimes%20000)
	fuzzFile, err := os.Create("fuzz-file")
	if err != nil {
		return 0
	}
	defer fuzzFile.Close()
	defer os.Remove("fuzz-file")
	_, err = fuzzFile.Write(fileContents)
	if err != nil {
		return 0
	}
	i := NewIndexFile()
	err = i.MustAdd(md, "fuzz-file", baseURL, digest)
	if err != nil {
		return 0
	}
	i.WriteFile("write-to-file", 0600)
	defer os.Remove("write-to-file")
	return 1
}

func FuzzIndexDirectory(data []byte) int {
	f := fuzz.NewConsumer(data)
	baseURL, err := f.GetString()
	if err != nil {
		return 0
	}

	err = os.Mkdir("indexdir", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("indexdir")
	err = f.CreateFiles("indexdir")
	if err != nil {
		return 0
	}
	_, _ = IndexDirectory("indexdir", baseURL)
	return 1
}

func FuzzDownloadIndexFile(data []byte) int {
	srv, err := startLocalServerForFuzzing(nil)
	if err != nil {
		return 0
	}
	defer srv.Close()
	r, err := NewChartRepository(&Entry{
		Name: "test-repo",
		URL:  srv.URL,
	}, getter.All(&cli.EnvSettings{}))
	if err != nil {
		return 0
	}

	idx, err := r.DownloadIndexFile()
	if err != nil {
		return 0
	}
	if _, err := os.Stat(idx); err != nil {
		return 0
	}
	i, err := LoadIndexFile(idx)
	if err != nil {
		return 0
	}
	// Check that charts file is also created
	idx = filepath.Join(r.CachePath, helmpath.CacheChartsFile(r.Config.Name))
	if _, err := os.Stat(idx); err != nil {
		panic(fmt.Sprintf("error finding created charts file: %#v", err))
	}

	b, err := ioutil.ReadFile(idx)
	if err != nil {
		panic(fmt.Sprintf("error reading charts file: %#v", err))
	}
	verifyLocalChartsFileFuzz(b, i)
	return 1
}

func startLocalServerForFuzzing(fileBytes []byte) (*httptest.Server, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fileBytes)
	})
	return httptest.NewServer(handler), nil
}

func verifyLocalChartsFileFuzz(chartsContent []byte, indexContent *IndexFile) {
	var expected, real []string
	for chart := range indexContent.Entries {
		expected = append(expected, chart)
	}
	sort.Strings(expected)

	scanner := bufio.NewScanner(bytes.NewReader(chartsContent))
	for scanner.Scan() {
		real = append(real, scanner.Text())
	}
	sort.Strings(real)

	if strings.Join(expected, " ") != strings.Join(real, " ") {
		panic(fmt.Sprintf("Cached charts file content unexpected. Expected:\n%s\ngot:\n%s", expected, real))
	}
}
