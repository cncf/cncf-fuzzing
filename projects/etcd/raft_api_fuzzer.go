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

package rafthttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"

	"go.etcd.io/etcd/api/v3/version"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/raft/v3/raftpb"
	"go.uber.org/zap"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzRaftHttpRequests(data []byte) int {
	body := bytes.NewReader(data)
	req, err := http.NewRequest("POST", "foo", body)
	if err != nil {
		return 0
	}
	req.Header.Set("X-Etcd-Cluster-ID", "0")
	req.Header.Set("X-Server-Version", version.Version)
	rw := httptest.NewRecorder()
	r := &fakeRaft{}
	h := newPipelineHandler(&Transport{Logger: zap.NewExample()}, r, types.ID(0))

	// goroutine because the handler panics to disconnect on raft error
	donec := make(chan struct{})
	go func() {
		defer func() {
			recover()
			close(donec)
		}()
		h.ServeHTTP(rw, req)
	}()
	<-donec
	return 1
}

func FuzzMessageEncodeDecode(data []byte) int {
	f := fuzz.NewConsumer(data)
	msg := raftpb.Message{}
	err := f.GenerateStruct(&msg)
	if err != nil {
		return 0
	}
	b := &bytes.Buffer{}
	enc := &messageEncoder{w: b}
	if err := enc.encode(&msg); err != nil {
		return 0
	}
	dec := &messageDecoder{r: b}
	_, _ = dec.decode()
	return 1
}
