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

package registry

import (
	"bytes"
	"context"
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	"github.com/phayes/freeport"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

var (
	fuzzWorkspaceDir         = "helm-registry-test"
	fuzzHtpasswdFileBasename = "authtest.htpasswd"
	fuzzUsername             = "myuser"
	fuzzPassword             = "mypass"
	quit                     = make(chan os.Signal, 1)
)

func FuzzGetTagMatchingVersionOrConstraint(data []byte) int {
	f := fuzz.NewConsumer(data)
	var tags []string
	err := f.CreateSlice(&tags)
	if err != nil {
		return 0
	}
	versionString, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = GetTagMatchingVersionOrConstraint(tags, versionString)
	return 1

}

func FuzzparseReference(data []byte) int {
	_, _ = parseReference(string(data))
	return 1
}

func setupRegistry() (*registry.Registry, *Client, string, error) {
	os.RemoveAll(fuzzWorkspaceDir)
	os.Mkdir(fuzzWorkspaceDir, 0700)

	var out bytes.Buffer
	credentialsFile := filepath.Join(fuzzWorkspaceDir, CredentialsFileBasename)

	// init test client
	var err error
	registryClient, err := NewClient(
		ClientOptDebug(true),
		ClientOptWriter(&out),
		ClientOptCredentialsFile(credentialsFile),
	)
	if err != nil {
		return nil, nil, "", err
	}

	// create htpasswd file (w BCrypt, which is required)
	pwBytes, err := bcrypt.GenerateFromPassword([]byte(fuzzPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, "", err
	}
	htpasswdPath := filepath.Join(fuzzWorkspaceDir, fuzzHtpasswdFileBasename)
	err = ioutil.WriteFile(htpasswdPath, []byte(fmt.Sprintf("%s:%s\n", fuzzUsername, string(pwBytes))), 0644)
	if err != nil {
		return nil, nil, "", err
	}

	// Registry config
	config := &configuration.Configuration{}
	port, err := freeport.GetFreePort()
	if err != nil {
		return nil, nil, "", err
	}
	dockerRegistryHost := fmt.Sprintf("localhost:%d", port)
	config.HTTP.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	config.HTTP.DrainTimeout = time.Duration(10) * time.Second
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	config.Auth = configuration.Auth{
		"htpasswd": configuration.Parameters{
			"realm": "localhost",
			"path":  htpasswdPath,
		},
	}
	config.Log.Level = "panic"
	dockerRegistry, err := registry.NewRegistry(context.Background(), config)
	if err != nil {
		return nil, nil, "", err
	}

	return dockerRegistry, registryClient, dockerRegistryHost, nil
}

func FuzzRegistryClient(data []byte) int {
	dockerRegistry, registryClient, dockerRegistryHost, err := setupRegistry()
	if err != nil {
		return 0
	}
	defer os.RemoveAll(fuzzWorkspaceDir)

	var errchan chan error
	go func() {
		errchan <- dockerRegistry.ListenAndServe()
	}()

	ref := fmt.Sprintf("%s/testrepo/testchart:1.2.3", dockerRegistryHost)
	_, _ = registryClient.Push(data, ref)
	_, _ = registryClient.Pull(ref)

	return 1
}
