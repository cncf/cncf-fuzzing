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
        "net/url"
        "testing"
        "strings"

        "github.com/opencontainers/go-digest"
        "github.com/sirupsen/logrus"

        "github.com/distribution/distribution/v3/reference"
        "github.com/distribution/distribution/v3/configuration"

)
func init() {
        logrus.SetLevel(logrus.PanicLevel)
}
func FuzzApp(data []byte) int {
    t := &testing.T{}
    config := configuration.Configuration{
            Storage: configuration.Storage{
                    "testdriver": configuration.Parameters{},
                    "maintenance": configuration.Parameters{"uploadpurging": map[interface{}]interface{}{
                            "enabled": false,
                    }},
            },
    }
    config.HTTP.Prefix = "/test/"
    config.HTTP.Headers = headerConfig

    env := newTestEnvWithConfig(t, &config)
    defer env.Shutdown()
    ref, _ := reference.WithName("foo/bar")
    uploadURLBaseAbs, _ := startPushLayer(t, env, ref)

    baseURL, err := env.builder.BuildBaseURL()
    if err != nil {
            return 0
    }

    parsed, _ := url.Parse(baseURL)
    if !strings.HasPrefix(parsed.Path, config.HTTP.Prefix) || err != nil {
            return 0
    }

    dgst := digest.FromBytes(data)

    resp, err := doPushLayer(t, env.builder, ref, dgst, uploadURLBaseAbs, bytes.NewReader(data))
    if err != nil {
            return 0
    }
    defer resp.Body.Close()

    return 1
}