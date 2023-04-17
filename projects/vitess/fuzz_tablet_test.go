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

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"

	topodatapb "vitess.io/vitess/go/vt/proto/topodata"
	"vitess.io/vitess/go/vt/topo/memorytopo"
)

func FuzzTabletCreation(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		tablets := make([]*topodatapb.Tablet, 0)
		ff.CreateSlice(&tablets)
		if len(tablets) < 2 {
			return
		}
		aliases := make([]*topodatapb.TabletAlias, 0)
		ctx := context.Background()
		ts := memorytopo.NewServer("cell1")
		for _, tablet := range tablets {
			err := ts.CreateTablet(ctx, tablet)
			if err == nil {
				aliases = append(aliases, tablet.Alias)
			}
		}
		for _, alias := range aliases {
			_, _ = ts.GetTablet(ctx, alias)
		}
	})
}
