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

package topotests

import (
	"context"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	_flag "vitess.io/vitess/go/internal/flag"
	topodatapb "vitess.io/vitess/go/vt/proto/topodata"
	"vitess.io/vitess/go/vt/topo/memorytopo"
)

func init() {
	_flag.TrickGlog()
}

func FuzzKeyspaceCreation(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		ks := make([]string, 0)
		ff.CreateSlice(&ks)
		if len(ks) < 2 {
			return
		}
		ts := memorytopo.NewServer("zone1")
		ctx := context.Background()
		var createdKs []string
		createdKs = make([]string, 0)
		for _, k := range ks {
			err := ts.CreateKeyspace(ctx, k, &topodatapb.Keyspace{})
			if err == nil {
				createdKs = append(createdKs, k)
			}
		}

		for _, k := range createdKs {
			_, err := ts.GetKeyspace(ctx, k)
			if err != nil {
				panic(err)
			}
			if ks == nil {
				panic("ks was nil")
			}
		}
	})
}
