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

package betesting

import (
	"testing"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.etcd.io/etcd/server/v3/storage/backend"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

func init() {
	testing.Init()
}

func fuzzUnsafePut(b backend.Backend, f *fuzz.ConsumeFuzzer) error {
	d1, err := f.GetBytes()
	if err != nil {
		return err
	}
	d2, err := f.GetBytes()
	if err != nil {
		return err
	}
	wtx := b.BatchTx()
	wtx.Lock()
	wtx.UnsafePut(schema.Key, d1, d2)
	wtx.Unlock()
	return nil
}

func fuzzUnsafeRange(b backend.Backend, f *fuzz.ConsumeFuzzer) error {
	d1, err := f.GetBytes()
	if err != nil {
		return err
	}
	d2, err := f.GetBytes()
	if err != nil {
		return err
	}
	rtx := b.ConcurrentReadTx()
	rtx.RLock()
	_, _ = rtx.UnsafeRange(schema.Key, d1, d2, 0)
	rtx.RUnlock()
	return nil
}

func FuzzBackend(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	f := fuzz.NewConsumer(data)
	t := &testing.T{}
	b, _ := NewTmpBackend(t, time.Hour, 10000)
	defer Close(t, b)

	wtx := b.BatchTx()
	wtx.Lock()
	wtx.UnsafeCreateBucket(schema.Key)
	wtx.Unlock()

	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfCalls%20; i++ {
		putApi, err := f.GetBool()
		if err != nil {
			return 0
		}
		if putApi {
			err := fuzzUnsafePut(b, f)
			if err != nil {
				return 0
			}
		} else {
			err = fuzzUnsafeRange(b, f)
			if err != nil {
				return 0
			}
		}
	}
	return 1
}
