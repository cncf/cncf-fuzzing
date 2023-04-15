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

var (
	ks  = "ks1"
	ctx = context.Background()
)

func FuzzShardCreation(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		s := make([]string, 0)
		ff.CreateSlice(&s)
		sUpdate := make([]string, 0)
		ff.CreateSlice(&sUpdate)
		if len(s) < 2 {
			return
		}
		var createdS []string
		createdS = make([]string, 0)
		ts := memorytopo.NewServer("zone1")
		err := ts.CreateKeyspace(ctx, ks, &topodatapb.Keyspace{})
		if err != nil {
			panic(err)
		}
		defer func() {
			for _, sh := range createdS {
				ts.DeleteShard(ctx, ks, sh)
			}
		}()

		for _, sh := range s {
			err := ts.CreateShard(ctx, ks, sh)
			if err == nil {
				createdS = append(createdS, sh)
			}
		}

		for _, sh := range createdS {
			_, err := ts.GetShard(ctx, ks, sh)
			if err != nil {
				panic(err)
			}
		}
	})
}
