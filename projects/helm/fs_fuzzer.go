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

package fs

import (
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"io/ioutil"
	"os"
	"path/filepath"
)

func FuzzfixLongPath(data []byte) int {
	f := fuzz.NewConsumer(data)
	dirname1, err := f.GetString()
	if err != nil {
		return -1
	}
	dir, err := ioutil.TempDir("", dirname1)
	if err != nil {
		return -1
	}
	defer os.RemoveAll(dir)

	filename1, err := f.GetString()
	if err != nil {
		return -1
	}
	srcfPath := filepath.Join(dir, filename1)
	srcf, err := os.Create(srcfPath)
	if err != nil {
		return -1
	}

	want, err := f.GetBytes()
	if err != nil {
		return -1
	}
	if _, err := srcf.Write(want); err != nil {
		return -1
	}
	srcf.Close()

	destfName, err := f.GetString()
	if err != nil {
		return -1
	}
	destf := filepath.Join(dir, destfName)
	if err := copyFile(srcf.Name(), destf); err != nil {
		return 0
	}

	got, err := ioutil.ReadFile(destf)
	if err != nil {
		return 0
	}

	got2, err := ioutil.ReadFile(srcfPath)
	if err != nil {
		return 0
	}

	if string(got2) != string(got) {
		fmt.Printf("expected: %s, got: %s\n", want, string(got))
		return 0
	}

	wantinfo, err := os.Stat(srcf.Name())
	if err != nil {
		return 0
	}

	gotinfo, err := os.Stat(destf)
	if err != nil {
		return 0
	}

	if wantinfo.Mode() != gotinfo.Mode() {
		panic(fmt.Sprintf("expected %s: %#v\n to be the same mode as %s: %#v", srcf.Name(), wantinfo.Mode(), destf, gotinfo.Mode()))
	}
	return 1
}
