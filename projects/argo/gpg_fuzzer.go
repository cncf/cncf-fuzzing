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

package gpg

import (
	"os"
	"path/filepath"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzImportPGPKeys(data []byte) int {
	dir, err := os.MkdirTemp("", "gpgdir-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)

	f := fuzz.NewConsumer(data)

	filename, err := f.GetString()
	if err != nil {
		return 0
	}

	filecontents, err := f.GetBytes()
	if err != nil {
		return 0
	}

	newFile, err := os.Create(filepath.Join(dir, filename))
	if err != nil {
		return 0
	}
	defer newFile.Close()

	_, err = newFile.Write(filecontents)
	if err != nil {
		return 0
	}

	err = os.MkdirAll("/app/config/gpg/keys", 0777)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("/app/config/gpg/keys")

	_, _ = ImportPGPKeys(filename)

	return 1
}
