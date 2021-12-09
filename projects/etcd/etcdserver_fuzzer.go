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

package etcdserver

import (
	"runtime"
	"strings"
	"sync"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/zap/zaptest"

	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/pkg/v3/wait"
	"go.etcd.io/etcd/raft/v3/raftpb"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/etcdserver/api/v2store"
	"go.etcd.io/etcd/server/v3/etcdserver/cindex"
	serverstorage "go.etcd.io/etcd/server/v3/storage"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

func init() {
	testing.Init()
}

// Fuzzapply runs into panics that should not happen in production
// but that might happen when fuzzing. catchPanics() catches those
// panics.
func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		}
		if !strings.Contains(err, "should never fail") {
			// Getting to this point means that the fuzzer
			// did not stop because of a manually added panic.
			panic(err)
		}
	}
}

// Fuzzapply tests func (s *EtcdServer).apply() with
// random entries.
func Fuzzapply(data []byte) int {
	defer catchPanics()

	f := fuzz.NewConsumer(data)

	// Create entries
	ents := make([]raftpb.Entry, 0)
	number, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < number%20; i++ {
		ent := raftpb.Entry{}
		err = f.GenerateStruct(&ent)
		if err != nil {
			return 0
		}
		if len(ent.Data) == 0 {
			return 0
		}
		ents = append(ents, ent)
	}
	if len(ents) == 0 {
		return 0
	}

	// Setup server
	t := &testing.T{}
	lg := zaptest.NewLogger(t)

	cl := membership.NewCluster(zaptest.NewLogger(t))
	cl.SetStore(v2store.New())
	cl.AddMember(&membership.Member{ID: types.ID(1)}, true)

	be, _ := betesting.NewDefaultTmpBackend(t)
	defer betesting.Close(t, be)

	schema.CreateMetaBucket(be.BatchTx())

	ci := cindex.NewConsistentIndex(be)
	srv := &EtcdServer{
		lgMu:         new(sync.RWMutex),
		lg:           lg,
		id:           1,
		r:            *realisticRaftNode(lg),
		cluster:      cl,
		w:            wait.New(),
		consistIndex: ci,
		beHooks:      serverstorage.NewBackendHooks(lg, ci),
	}

	// Pass entries to (s *EtcdServer).apply()
	_, _, _ = srv.apply(ents, &raftpb.ConfState{})
	return 1
}
