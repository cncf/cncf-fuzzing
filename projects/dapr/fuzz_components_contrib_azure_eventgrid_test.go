// Copyright 2023 the cncf-fuzzing authors
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

package eventgrid

import (
	"context"
	"testing"
	"github.com/dapr/kit/logger"
	"github.com/dapr/components-contrib/bindings" 
)

var (
	log = logger.NewLogger("test")
	eh = AzureEventGrid{}
	m = bindings.Metadata{}
)

func init() {
	log.SetOutputLevel(logger.FatalLevel)
	eh.logger = log
	m.Properties = map[string]string {
		"azureClientID": "fuzz",
	}
	meta, err := eh.parseMetadata(m)
	if err != nil {
		panic(err)
	}
	eh.metadata = meta
}


func FuzzAzureEventGridTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, authorizationHeader string) {
		eh.validateAuthHeader(context.Background(), authorizationHeader)
	})
}
