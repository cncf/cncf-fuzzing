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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func walkDir(dirPath string, fileMap map[string]string) error {
	err := filepath.Walk(dirPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				dat, err := os.ReadFile(path)
				if err != nil {
					panic(err)
				}
				escapedString := strings.Replace(string(dat), "`", "", -1)
				fileMap[path] = escapedString
			}
			return nil
		})
	return err
}

// Checks whether the directory of a filename exists.
// If it doesn't exists, then it is created.
func checkOrCreateDir(fileNamePath string) error {
	path := filepath.Dir(fileNamePath)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}

func createFile(fileMap map[string]string) error {
	var builder strings.Builder
	builder.WriteString("package envtest\n\n")
	builder.WriteString("var CrdMap = map[string]string{")

	for k, v := range fileMap {
		k2 := strings.Replace(k, "/src/cluster-api", ".", -1)
		builder.WriteString("\"" + k2 + "\":`" + v + "`,\n")
		//fmt.Println(filepath.Dir(k))
	}
	builder.WriteString("}\n")
	f, err := os.Create("/src/cluster-api/internal/test/envtest/static_crds.go")
	if err != nil {
		panic(err)
	}

	defer f.Close()
	_, err = f.WriteString(builder.String())
	if err != nil {
		panic(err)
	}
	return nil
}

func compareFileMaps(fileMap map[string]string) {
	/*for k, v := range fileMap {
		if crdMap[k] != fileMap[k] {
			panic("they should be similar")
		}
	}*/
}

func main() {
	dirPaths := []string{"/src/cluster-api/config/crd/bases",
		"/src/cluster-api/controlplane/kubeadm/config/crd/bases",
		"/src/cluster-api/bootstrap/kubeadm/config/crd/bases",
		"/src/cluster-api/config/webhook",
		"/src/cluster-api/bootstrap/kubeadm/config/webhook",
		"/src/cluster-api/controlplane/kubeadm/config/webhook",
	}

	fileMap := make(map[string]string)
	for _, dirPath := range dirPaths {
		err := walkDir(dirPath, fileMap)
		if err != nil {
			panic(err)
		}
	}
	err := createFile(fileMap)
	if err != nil {
		panic(err)
	}
	fmt.Println("Created static crds")

}
