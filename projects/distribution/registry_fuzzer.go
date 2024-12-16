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

package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/distribution/distribution/v3/configuration"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
)

func init() {
	filename := "/tmp/logfile"
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	log.SetOutput(f)
	log.SetLevel(log.PanicLevel)
}

func setupRegistry2(tlsCfg *registryTLSConfig, addr string) (*Registry, *configuration.Configuration, error) {
	config := &configuration.Configuration{}
	config.HTTP.Addr = addr
	config.HTTP.DrainTimeout = time.Duration(100) * time.Millisecond
	if tlsCfg != nil {
		config.HTTP.TLS.CipherSuites = tlsCfg.cipherSuites
		config.HTTP.TLS.Certificate = tlsCfg.certificatePath
		config.HTTP.TLS.Key = tlsCfg.privateKeyPath
	}
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}

	registry, err := NewRegistry(context.Background(), config)
	return registry, config, err
}

// Because registry.NewRegistry leaks memory,
// we are considerate about how many times
// we call that API. Before we call it we
// need to have at least 100 payloads.
func FuzzRegistry1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)

		// Create the payloads here:
		noOfExecs, err := fdp.GetInt()
		if err != nil {
			return
		}
		if noOfExecs == 0 {
			return
		}
		maxExecs := 2000
		if noOfExecs%maxExecs < 250 {
			return
		}
		payloads := make([]string, 0)
		for i := 0; i < noOfExecs%maxExecs; i++ {
			payload, err := fdp.GetString()
			if err != nil {
				return
			}
			payloads = append(payloads, payload)
		}

		// Start the server
		registry, config, err := setupRegistry2(nil, ":5000")
		if err != nil {
			panic(err)
		}
		go func() {
			registry.ListenAndServe()
		}()
		time.Sleep(100 * time.Millisecond)
		c, cancel := context.WithTimeout(context.Background(), config.HTTP.DrainTimeout)
		defer cancel()
		defer func() {
			registry.server.Shutdown(c)
		}()
		conn, err := net.Dial("tcp", "localhost:5000")
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		// Send the payloads
		for _, payload := range payloads {
			fmt.Fprintf(conn, payload)
		}
	})
}

func FuzzRegistry2(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		name := "registry_test_server_supported_cipher"
		cipherSuites := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
		serverTLS, err := buildRegistryTLSConfig(name, "rsa", cipherSuites)
		registry, config, err := setupRegistry2(serverTLS, ":5000")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = config
		go func() {
			registry.ListenAndServe()
		}()
		clientTLS := tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}
		dialer := net.Dialer{
			Timeout: time.Second * 1,
		}
		conn, err := tls.DialWithDialer(&dialer, "tcp", "127.0.0.1:5000", &clientTLS)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer conn.Close()
		noOfExecs, err := fdp.GetInt()
		if err != nil {
			return
		}
		maxExecs := 200
		for i := 0; i < noOfExecs%maxExecs; i++ {
			payload, err := fdp.GetString()
			if err != nil {
				return
			}
			fmt.Fprintf(conn, payload)
		}
	})
}
