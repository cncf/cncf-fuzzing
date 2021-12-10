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

package mvcc

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"go.etcd.io/etcd/server/v3/lease"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.uber.org/zap"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	testing.Init()
}

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		}
		if shouldReport(err) {
			// Getting to this point means that the fuzzer
			// did not stop because of a manually added panic.
			panic(err)
		}
	}
}

func shouldReport(err string) bool {
	if strings.Contains(err, "failed to open database") {
		return false
	}
	return true
}

func FuzzMvccStorage(data []byte) int {
	defer catchPanics()
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	b1, err := f.GetBytes()
	if err != nil {
		return 0
	}
	b2, err := f.GetBytes()
	if err != nil {
		return 0
	}
	b3, err := f.GetBytes()
	if err != nil {
		return 0
	}
	b4, err := f.GetBytes()
	if err != nil {
		return 0
	}
	b5, err := f.GetBytes()
	if err != nil {
		return 0
	}
	b6, err := f.GetBytes()
	if err != nil {
		return 0
	}

	b, tmpPath := betesting.NewDefaultTmpBackend(t)
	s := NewStore(zap.NewExample(), b, &lease.FakeLessor{}, StoreConfig{})
	defer os.Remove(tmpPath)

	ro := RangeOptions{Limit: 1, Rev: 0, Count: false}

	done := make(chan struct{}, 1)
	go func() {
		s.Put(b1, b2, lease.NoLease)
		_, _ = s.Range(context.Background(), b3, b4, ro)
		_, _ = s.DeleteRange(b5, b6)
		done <- struct{}{}
	}()

	return 1
}
