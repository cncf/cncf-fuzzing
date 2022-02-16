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

package kayenta

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "Incorrect url") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzKayenta(data []byte) int {
	defer catchPanics()
	f := fuzz.NewConsumer(data)
	metric := v1alpha1.Metric{}
	err := f.GenerateStruct(&metric)
	if err != nil {
		return 0
	}
	e := log.NewEntry(log.New())
	c := NewTestClient(func(req *http.Request) *http.Response {
		if req.URL.String() == jobURL {
			if req.URL.String() != jobURL {
				panic("Incorrect url")
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				panic(err)
			}
			bodyI := map[string]interface{}{}
			err = json.Unmarshal(body, &bodyI)
			if err != nil {
				panic("Could not marshal")
			}
			expectedBodyI := map[string]interface{}{}
			err = json.Unmarshal([]byte(expectedBody), &expectedBodyI)
			if err != nil {
				panic("Could not marshal")
			}
			return &http.Response{
				StatusCode: 200,
				// Send response to be tested
				Body: ioutil.NopCloser(bytes.NewBufferString(`
                        {
                                "canaryExecutionId" : "01DS50WVHAWSTAQACJKB1VKDQB"
            }
                        `)),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		} else {
			url := req.URL.String()
			if url != lookupURL {
				panic("Incorrect url")
			}

			return &http.Response{
				StatusCode: 200,
				// Send response to be tested
				Body: ioutil.NopCloser(bytes.NewBufferString(configIdLookupResponse)),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		}
	})

	p := NewKayentaProvider(*e, c)

	stableHash := "xxxx"
	canaryHash := "yyyy"
	startTime := "2019-03-29T01:08:34Z"
	endTime := "2019-03-29T01:38:34Z"
	run := newAnalysisRun()
	run.Spec.Args = []v1alpha1.Argument{
		{Name: "start-time", Value: &startTime},
		{Name: "end-time", Value: &endTime},
		{Name: "stable-hash", Value: &stableHash},
		{Name: "canary-hash", Value: &canaryHash},
	}
	_ = p.GetMetadata(metric)

	measurement := p.Run(run, metric)
	_ = p.Terminate(run, metric, measurement)
	return 1
}
