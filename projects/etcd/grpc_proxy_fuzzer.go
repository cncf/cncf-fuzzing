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

package fuzzing

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"google.golang.org/grpc"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/proxy/grpcproxy"
	integration2 "go.etcd.io/etcd/tests/v3/framework/integration"
)

var (
	initFuzzKVProxy sync.Once

	URLScheme           = "unix"
	URLSchemeTLS        = "unixs"
	availableOperations = map[int]string{
		0: "Put",
		1: "Range",
		2: "DeleteRange",
	}
)

func initFuncFuzzKVProxy() {
	testing.Init()

}

func validatePutRequest(r *pb.PutRequest) error {
	if r.Key == nil {
		return fmt.Errorf("r.Key is nil")
	}
	if r.Value == nil {
		return fmt.Errorf("r.Value is nil")
	}
	return nil
}

func validateDeleteRangeRequest(r *pb.DeleteRangeRequest) error {
	if r.Key == nil {
		return fmt.Errorf("r.Key is nil")
	}
	if r.RangeEnd == nil {
		return fmt.Errorf("r.RangeEnd is nil")
	}
	return nil
}

func validateRangeRequest(r *pb.RangeRequest) error {
	if r.Key == nil {
		return fmt.Errorf("r.Key is nil")
	}
	if r.RangeEnd == nil {
		return fmt.Errorf("r.RangeEnd is nil")
	}
	return nil
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
		if strings.Contains(err, "failed to create WAL") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzKVProxy(data []byte) int {
	defer catchPanics()
	initFuzzKVProxy.Do(initFuncFuzzKVProxy)
	t1 := &testing.T{}
	f := fuzz.NewConsumer(data)
	oh := newrequestHolder(f)
	err := oh.createRequests()
	if err != nil {
		return 0
	}
	if len(oh.opCodes) < 10 {
		return 0
	}

	defer cleanupDir()
	clus := integration2.NewCluster(t1, &integration2.ClusterConfig{Size: 1})

	defer clus.Terminate(t1)

	kvts := newKVProxyServer([]string{clus.Members[0].GRPCURL}, t1)
	defer kvts.close()

	oh.kp = kvts.kp
	for _, op := range oh.opCodes {
		oh.makeRequest(op)
	}
	return 1
}

type requestHolder struct {
	kp                    pb.KVServer
	f                     *fuzz.ConsumeFuzzer
	putOperations         []*pb.PutRequest
	rangeOperations       []*pb.RangeRequest
	deleteRangeOperations []*pb.DeleteRangeRequest
	opCodes               []int
}

func newrequestHolder(f *fuzz.ConsumeFuzzer) *requestHolder {
	oh := &requestHolder{}
	po := make([]*pb.PutRequest, 0)
	ro := make([]*pb.RangeRequest, 0)
	dro := make([]*pb.DeleteRangeRequest, 0)
	opCodes := make([]int, 0)
	oh.putOperations = po
	oh.rangeOperations = ro
	oh.deleteRangeOperations = dro
	oh.opCodes = opCodes
	oh.f = f
	return oh
}

func (oh *requestHolder) createRequests() error {
	numOfRequests, err := oh.f.GetInt()
	if err != nil {
		return err
	}
	for i := 0; i < numOfRequests%30; i++ {
		opType, err := oh.f.GetInt()
		if err != nil {
			return err
		}
		switch availableOperations[opType%len(availableOperations)] {
		case "Put":
			r, err := createPutRequest(oh.f)
			if err != nil {
				return err
			}
			oh.putOperations = append(oh.putOperations, r)
			oh.opCodes = append(oh.opCodes, 0)
		case "Range":
			r, err := createRangeRequest(oh.f)
			if err != nil {
				return err
			}
			oh.rangeOperations = append(oh.rangeOperations, r)
			oh.opCodes = append(oh.opCodes, 1)
		case "DeleteRange":
			r, err := createDeleteRangeRequest(oh.f)
			if err != nil {
				return err
			}
			oh.deleteRangeOperations = append(oh.deleteRangeOperations, r)
			oh.opCodes = append(oh.opCodes, 2)
		}
	}
	return nil
}

func createPutRequest(f *fuzz.ConsumeFuzzer) (*pb.PutRequest, error) {
	pr := &pb.PutRequest{}
	err := f.GenerateStruct(pr)
	if err != nil {
		return nil, err
	}
	err = validatePutRequest(pr)
	if err != nil {
		return nil, err
	}
	return pr, nil
}

func createRangeRequest(f *fuzz.ConsumeFuzzer) (*pb.RangeRequest, error) {
	rr := &pb.RangeRequest{}
	err := f.GenerateStruct(rr)
	if err != nil {
		return nil, err
	}
	err = validateRangeRequest(rr)
	if err != nil {
		return nil, err
	}
	return rr, nil
}

func createDeleteRangeRequest(f *fuzz.ConsumeFuzzer) (*pb.DeleteRangeRequest, error) {
	dr := &pb.DeleteRangeRequest{}
	err := f.GenerateStruct(dr)
	if err != nil {
		return nil, err
	}
	err = validateDeleteRangeRequest(dr)
	if err != nil {
		return nil, err
	}
	return dr, nil
}

func (oh *requestHolder) makeRequest(op int) {
	switch availableOperations[op] {
	case "Put":
		oh.makePutRequest()
	case "Range":
		oh.makeRangeRequest()
	case "DeleteRange":
		oh.makeDeleteRangeRequest()
	}
}

func (oh *requestHolder) makePutRequest() {
	r := oh.putOperations[0]
	_, _ = oh.kp.Put(context.Background(), r)
	oh.putOperations = oh.putOperations[1:]
	oh.opCodes = oh.opCodes[1:]
}

func (oh *requestHolder) makeRangeRequest() {
	r := oh.rangeOperations[0]
	_, _ = oh.kp.Range(context.Background(), r)
	oh.rangeOperations = oh.rangeOperations[1:]
	oh.opCodes = oh.opCodes[1:]
}

func (oh *requestHolder) makeDeleteRangeRequest() {
	r := oh.deleteRangeOperations[0]
	_, _ = oh.kp.DeleteRange(context.Background(), r)
	oh.deleteRangeOperations = oh.deleteRangeOperations[1:]
	oh.opCodes = oh.opCodes[1:]
}

type kvproxyTestServer struct {
	kp     pb.KVServer
	c      *clientv3.Client
	server *grpc.Server
	l      net.Listener
}

func (kts *kvproxyTestServer) close() {
	kts.server.Stop()
	kts.l.Close()
	kts.c.Close()
}

func newKVProxyServer(endpoints []string, t *testing.T) *kvproxyTestServer {
	cfg := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	}
	client, err := integration2.NewClient(t, cfg)
	if err != nil {
		t.Fatal(err)
	}

	kvp, _ := grpcproxy.NewKvProxy(client)

	kvts := &kvproxyTestServer{
		kp: kvp,
		c:  client,
	}

	var opts []grpc.ServerOption
	kvts.server = grpc.NewServer(opts...)
	pb.RegisterKVServer(kvts.server, kvts.kp)

	kvts.l, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go kvts.server.Serve(kvts.l)

	return kvts
}

// A cluster creates files named "127.0.0.1:*" and "localhost:*",
// and these are deleted after each iteration.
func cleanupDir() {
	items, err := os.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, item := range items {
		if strings.Contains(item.Name(), "127.0.0.1:") {
			os.RemoveAll(item.Name())
			//fmt.Println(item.Name())
		} else if strings.Contains(item.Name(), "localhost:") {
			os.RemoveAll(item.Name())
		}
	}
}
