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
	"reflect"
	"runtime"
	"strings"
	"testing"

	"go.etcd.io/etcd/server/v3/lease"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

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

func catchFuzzMvccIndex() {
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
		if strings.Contains(err, "'put' with an unexpected smaller revision") {
			return
		} else {
			panic(err)
		}
	}

}

func FuzzMvccIndex(data []byte) int {
	defer catchFuzzMvccIndex()
	ops := map[int]string{
		0: "Put",
		1: "Get",
		2: "Range",
		3: "Equal",
	}
	f := fuzz.NewConsumer(data)
	t := &testing.T{}
	lg := zaptest.NewLogger(t, zaptest.Level(zapcore.FatalLevel))
	ti := newTreeIndex(lg)

	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}

	for i := 0; i < noOfCalls%10; i++ {
		opType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch ops[opType] {
		case "Put":
			putBytes, err := f.GetBytes()
			if err != nil {
				return 0
			}
			rev, err := createRev(f)
			if err != nil {
				return 0
			}
			ti.Put(putBytes, rev)
		case "Get":
			getBytes, err := f.GetBytes()
			if err != nil {
				return 0
			}
			atRev, err := f.GetInt()
			if err != nil {
				return 0
			}
			_, _, _, _ = ti.Get(getBytes, int64(atRev))
		case "Range":
			key, err := f.GetBytes()
			if err != nil {
				return 0
			}
			end, err := f.GetBytes()
			if err != nil {
				return 0
			}
			atRev, err := f.GetInt()
			if err != nil {
				return 0
			}
			_, _ = ti.Range(key, end, int64(atRev))
		case "Equal":
			numb, err := f.GetInt()
			if err != nil {
				return 0
			}
			newInd, err := f.GetInt()
			if err != nil {
				return 0
			}
			am := ti.Compact(int64(newInd))
			keep := ti.Keep(int64(newInd))
			if !(reflect.DeepEqual(am, keep)) {
				return 0
			}
			lg2 := zaptest.NewLogger(t, zaptest.Level(zapcore.FatalLevel))
			wti := newTreeIndex(lg2)
			for i := 0; i < numb%10; i++ {
				rev1, err := createRev(f)
				if err != nil {
					return 0
				}
				rev2, err := createRev(f)
				if err != nil {
					return 0
				}
				key, err := f.GetBytes()
				if err != nil {
					return 0
				}
				ver, err := f.GetInt()
				if err != nil {
					return 0
				}
				created, err := createRev(f)
				if err != nil {
					return 0
				}
				if _, ok := am[rev1]; ok || rev1.GreaterThan(rev2) {
					remove, err := f.GetBool()
					if err != nil {
						return 0
					}
					if remove {
						wti.Tombstone(key, rev1)
					} else {
						restoreFuzz(wti.(*treeIndex), key, created, rev1, int64(ver))
					}
				}
			}
			_ = ti.Equal(wti)
		}
	}
	return 1
}

func createRev(f *fuzz.ConsumeFuzzer) (Revision, error) {
	mainInt64, err := f.GetInt()
	if err != nil {
		return Revision{}, err
	}
	subInt64, err := f.GetInt()
	if err != nil {
		return Revision{}, err
	}
	return Revision{Main: int64(mainInt64), Sub: int64(subInt64)}, nil
}

func restoreFuzz(ti *treeIndex, key []byte, created, modified Revision, ver int64) {
	keyi := &keyIndex{key: key}

	ti.Lock()
	defer ti.Unlock()
	item, ok := ti.tree.Get(keyi)
	if !ok {
		keyi.restore(ti.lg, created, modified, ver)
		ti.tree.ReplaceOrInsert(keyi)
		return
	}
	okeyi := item
	okeyi.put(ti.lg, modified.Main, modified.Sub)
}
