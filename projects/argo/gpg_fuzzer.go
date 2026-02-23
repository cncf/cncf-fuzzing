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
)

var (
	gpgKeyFile string
)

func init() {
	dir, err := os.MkdirTemp("", "gpgdir-")
	if err != nil {
		panic(err)
	}
	gpgKeyFile = filepath.Join(dir, "fuzz_key")
}

func FuzzImportPGPKeys(data []byte) int {
	if err := os.WriteFile(gpgKeyFile, data, 0644); err != nil {
		return 0
	}
	if err := os.MkdirAll("/app/config/gpg/keys", 0777); err != nil {
		return 0
	}
	defer os.RemoveAll("/app/config/gpg/keys")
	_, _ = ImportPGPKeys(gpgKeyFile)
	return 1
}

func FuzzValidatePGPKeysFromString(data []byte) int {
	_, _ = ValidatePGPKeysFromString(string(data))
	return 1
}
