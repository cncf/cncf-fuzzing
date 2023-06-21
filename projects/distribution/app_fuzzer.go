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

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"

	"github.com/distribution/distribution/v3/configuration"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/distribution/v3/reference"
	v2 "github.com/distribution/distribution/v3/registry/api/v2"
	"github.com/docker/libtrust"
)

func init() {
	logrus.SetLevel(logrus.PanicLevel)
}
func FuzzApp(data []byte) int {
	config := configuration.Configuration{
		Storage: configuration.Storage{
			"inmemory": configuration.Parameters{},
			"maintenance": configuration.Parameters{"uploadpurging": map[interface{}]interface{}{
				"enabled": false,
			}},
		},
	}
	config.HTTP.Prefix = "/test/"
	config.HTTP.Headers = headerConfig

	logFile, err := os.OpenFile("/tmp/text.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0
	}
	defer logFile.Close()

	env, err := newFuzzEnvWithConfig(&config, logFile)
	if err != nil {
		return 0
	}
	defer env.Shutdown()
	ref, _ := reference.WithName("foo/bar")
	uploadURLBaseAbs, _, err := startFuzzPushLayer(env, ref)
	if err != nil || uploadURLBaseAbs == "" {
		return 0
	}

	baseURL, err := env.builder.BuildBaseURL()
	if err != nil {
		return 0
	}

	parsed, _ := url.Parse(baseURL)
	if !strings.HasPrefix(parsed.Path, config.HTTP.Prefix) || err != nil {
		return 0
	}

	dgst := digest.FromBytes(data)

	resp, err := doPushLayerFuzz(ref, dgst, uploadURLBaseAbs, bytes.NewReader(data))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	return 1
}

func newFuzzEnvWithConfig(config *configuration.Configuration, logFile *os.File) (*testEnv, error) {
	ctx := context.Background()

	app := NewApp(ctx, config)
	//server := httptest.NewServer(handlers.CombinedLoggingHandler(logFile, app))
	server := httptest.NewServer(app)
	builder, err := v2.NewURLBuilderFromString(server.URL+config.HTTP.Prefix, false)

	if err != nil {
		return nil, err
	}

	pk, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		return nil, err
	}

	return &testEnv{
		pk:      pk,
		ctx:     ctx,
		config:  *config,
		app:     app,
		server:  server,
		builder: builder,
	}, nil
}

func startFuzzPushLayer(env *testEnv, name reference.Named) (string, string, error) {
	layerUploadURL, err := env.builder.BuildBlobUploadURL(name)
	if err != nil {
		return "", "", err
	}

	u, err := url.Parse(layerUploadURL)
	if err != nil {
		return "", "", err
	}

	base, err := url.Parse(env.server.URL)
	if err != nil {
		return "", "", err
	}

	layerUploadURL = base.ResolveReference(u).String()
	resp, err := http.Post(layerUploadURL, "", nil)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	defer resp.Body.Close()
	bs, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		fmt.Println(string(bs))
	}

	err = checkResponseFuzz(fmt.Sprintf("pushing starting layer push %v", name.String()), resp, http.StatusAccepted)
	if err != nil {
		return "", "", err
	}

	u, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}

	uuid := path.Base(u.Path)

	return resp.Header.Get("Location"), uuid, nil
}

func checkResponseFuzz(msg string, resp *http.Response, expectedStatus int) error {
	if resp.StatusCode != expectedStatus {
		err := maybeDumpResponseFuzz(resp)
		if err != nil {
			return err
		}
	}

	// We expect the headers included in the configuration, unless the
	// status code is 405 (Method Not Allowed), which means the handler
	// doesn't even get called.
	if resp.StatusCode != 405 && !reflect.DeepEqual(resp.Header["X-Content-Type-Options"], []string{"nosniff"}) {
		err := maybeDumpResponseFuzz(resp)
		if err != nil {
			return err
		}
	}
	return nil
}

func maybeDumpResponseFuzz(resp *http.Response) error {
	if _, err := httputil.DumpResponse(resp, true); err != nil {
		return err
	} else {
		return nil
	}
}

// doPushLayerFuzz pushes the layer content returning the url on success returning
// the response. If you're only expecting a successful response, use pushLayer.
func doPushLayerFuzz(name reference.Named, dgst digest.Digest, uploadURLBase string, body io.Reader) (*http.Response, error) {
	//fmt.Println("uploadURLBas: ", uploadURLBase)
	u, err := url.Parse(uploadURLBase)
	if err != nil {
		return nil, err
	}

	u.RawQuery = url.Values{
		"_state": u.Query()["_state"],
		"digest": []string{dgst.String()},
	}.Encode()

	uploadURL := u.String()
	//fmt.Println("UploadURL: ", uploadURL)
	// Just do a monolithic upload
	req, err := http.NewRequest("PUT", uploadURL, body)
	if err != nil {
		return nil, err
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	bs, err := ioutil.ReadAll(r.Body)
	if err == nil {
		fmt.Println(string(bs))
	}
	return r, nil
}

func checkHeadersFuzz(resp *http.Response, headers http.Header) error {
	for k, vs := range headers {
		if resp.Header.Get(k) == "" {
			return fmt.Errorf("err")
		}

		for _, v := range vs {
			if v == "*" {
				// Just ensure there is some value.
				if len(resp.Header[http.CanonicalHeaderKey(k)]) > 0 {
					return fmt.Errorf("err")
				}
			}

			for _, hv := range resp.Header[http.CanonicalHeaderKey(k)] {
				if hv != v {
					return fmt.Errorf("err")
				}
			}
		}
	}
	return nil
}
