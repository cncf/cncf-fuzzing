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

package wal

import (
	"bytes"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"go.etcd.io/etcd/server/v3/storage/wal/walpb"
	"go.etcd.io/raft/v3/raftpb"
	"go.uber.org/zap"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzWalCreate(data []byte) int {
	p, err := ioutil.TempDir("/tmp", "waltest")
	if err != nil {
		return -1
	}
	defer os.RemoveAll(p)
	w, err := Create(zap.NewExample(), p, data)
	if err != nil {
		return 0
	}
	if err = w.SaveSnapshot(walpb.Snapshot{}); err != nil {
		return 0
	}
	if err = w.Save(raftpb.HardState{}, []raftpb.Entry{{Index: 0}}); err != nil {
		return 0
	}
	w.Close()
	neww, err := Open(zap.NewExample(), p, walpb.Snapshot{})
	if err != nil {
		return 0
	}
	defer neww.Close()
	metadata, _, _, err := neww.ReadAll()
	if err != nil {
		return 0
	}
	if !bytes.Equal(data, metadata) {
		panic("data and metadata are not equal, but they should be")
	}
	return 1
}

// All cases in shouldReport represent known errors in etcd
// as these are reported via manually added panics.
func shouldReport(err string) bool {

	// "GOT A FUZZ ERROR" is placed in all panics in
	// server/storage/wal/version.go.
	if strings.Contains(err, "GOT A FUZZ ERROR") {
		return false
	}

	return true
}

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
		if shouldReport(err) {
			// Getting to this point means that the fuzzer
			// did not stop because of a manually added panic.
			panic(err)
		}
	}
}

func FuzzMinimalEtcdVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	noOfEnts, err := f.GetInt()
	if err != nil {
		return 0
	}
	ents := make([]raftpb.Entry, 0)
	for i := 0; i < noOfEnts%10; i++ {
		newEnt := raftpb.Entry{}
		err = f.GenerateStruct(&newEnt)
		if err != nil {
			return 0
		}
		ents = append(ents, newEnt)
	}
	defer catchPanics()
	_ = MinimalEtcdVersion(ents)
	return 1
}
