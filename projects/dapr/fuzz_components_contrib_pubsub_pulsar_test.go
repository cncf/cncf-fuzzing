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

package pulsar

import (
	"testing"

	"github.com/dapr/components-contrib/pubsub"
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
)

var (
	protocols = map[int]string {
		0: jsonProtocol,
		1: avroProtocol,
	}
)


func FuzzAvroTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)

		req := &pubsub.PublishRequest{}
		ff.GenerateStruct(req)

		i, err := ff.GetInt()
		if err != nil {
			return
		}
		protocol := protocols[i%len(protocols)]

		value, err := ff.GetString()
		if err != nil {
			return
		}

		schema := schemaMetadata{
			protocol: protocol,
			value: value,
		}

		parsePublishMetadata(req, schema)
	})
}
