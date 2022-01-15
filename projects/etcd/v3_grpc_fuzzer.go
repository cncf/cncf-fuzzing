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
	"os"
	"strings"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/tests/v3/framework/integration"
)

var (
	requestTypes = map[int]string{0: "putRequest",
		1: "rangeRequest",
		2: "deleteRequest",
		3: "txnRequest",
		4: "compactionRequest"}
	maxRequestTypes    = len(requestTypes)
	t2                 = &testing.T{}
	putRequests        []*pb.PutRequest
	rangeRequests      []*pb.RangeRequest
	deleteRequests     []*pb.DeleteRangeRequest
	txnRequests        []*pb.TxnRequest
	compactionRequests []*pb.CompactionRequest
)

func resetRequests() {
	putRequests = make([]*pb.PutRequest, 0)
	rangeRequests = make([]*pb.RangeRequest, 0)
	deleteRequests = make([]*pb.DeleteRangeRequest, 0)
	txnRequests = make([]*pb.TxnRequest, 0)
	compactionRequests = make([]*pb.CompactionRequest, 0)
}

func createRequests(f *fuzz.ConsumeFuzzer) error {
	numberOfRequests, err := f.GetInt()
	if err != nil {
		return err
	}
	maxRequests := numberOfRequests % 300
	for i := 0; i < maxRequests; i++ {
		requestType, err := f.GetInt()
		if err != nil {
			return err
		}
		err = createRequest(f, requestType%maxRequestTypes)
		if err != nil {
			return err
		}
	}
	return nil
}

func createRequest(f *fuzz.ConsumeFuzzer, requestType int) error {
	switch requestTypes[requestType] {
	case "putRequest":
		req := &pb.PutRequest{}
		err := f.GenerateStruct(req)
		if err != nil {
			return err
		}
		putRequests = append(putRequests, req)
	case "rangeRequest":
		req := &pb.RangeRequest{}
		err := f.GenerateStruct(req)
		if err != nil {
			return err
		}
		rangeRequests = append(rangeRequests, req)
	case "deleteRequest":
		req := &pb.DeleteRangeRequest{}
		err := f.GenerateStruct(req)
		if err != nil {
			return err
		}
		deleteRequests = append(deleteRequests, req)
	case "txnRequest":
		req := &pb.TxnRequest{}
		err := f.GenerateStruct(req)
		if err != nil {
			return err
		}
		txnRequests = append(txnRequests, req)
	case "compactionRequest":
		req := &pb.CompactionRequest{}
		err := f.GenerateStruct(req)
		if err != nil {
			return err
		}
		compactionRequests = append(compactionRequests, req)
	}
	return nil
}

func createExecutionOrder(f *fuzz.ConsumeFuzzer) ([]int, error) {
	prLen := len(putRequests)
	rrLen := len(rangeRequests)
	drLen := len(deleteRequests)
	trLen := len(txnRequests)
	crLen := len(compactionRequests)
	totalLength := prLen + rrLen + drLen + trLen + crLen
	executionList := make([]int, totalLength)
	for i := 0; i < totalLength; i++ {
		opType, err := f.GetInt()
		if err != nil {
			return executionList, err
		}
		executionList = append(executionList, opType%maxRequestTypes)
	}
	return executionList, nil
}

func availableRequests() int {
	return len(putRequests) + len(rangeRequests) + len(deleteRequests) + len(txnRequests) + len(compactionRequests)
}

func FuzzGRPCApis(data []byte) int {
	resetRequests()
	f := fuzz.NewConsumer(data)

	// Create requests
	err := createRequests(f)
	if err != nil {
		return 0
	}

	// Since the initialization of etcd is quite expensive for this fuzzer,
	// we only do said initialization once there are at least 40 requests to make.
	if availableRequests() < 40 {
		return 0
	}

	// Create the order of the requests
	executionOrder, err := createExecutionOrder(f)
	if err != nil {
		return 0
	}

	// Create test cluster
	defer cleanupDir()
	clus, err := integration.NewClusterV3Fuzz(t2, &integration.ClusterConfig{Size: 3}, f)
	if err != nil {
		return 0
	}
	defer clus.Terminate(t2)
	defer cleanUpDir()

	kvc := integration.ToGRPC(clus.RandClient()).KV

	// Send the requests
	for i := 0; i < len(executionOrder); i++ {
		switch requestTypes[executionOrder[i]] {
		case "putRequest":
			if len(putRequests) == 0 {
				continue
			}
			_, _ = kvc.Put(context.Background(), putRequests[0])
			// remove the executed request:
			putRequests = putRequests[1:]
		case "rangeRequest":
			if len(rangeRequests) == 0 {
				continue
			}
			_, _ = kvc.Range(context.Background(), rangeRequests[0])
			// remove the executed request:
			rangeRequests = rangeRequests[1:]
		case "deleteRequest":
			if len(deleteRequests) == 0 {
				continue
			}
			_, _ = kvc.DeleteRange(context.Background(), deleteRequests[0])
			// remove the executed request:
			deleteRequests = deleteRequests[1:]
		case "txnRequest":
			if len(txnRequests) == 0 {
				continue
			}
			_, _ = kvc.Txn(context.Background(), txnRequests[0])
			// remove the executed request:
			txnRequests = txnRequests[1:]
		case "compactionRequest":
			if len(compactionRequests) == 0 {
				continue
			}
			_, _ = kvc.Compact(context.Background(), compactionRequests[0])
			// remove the executed request:
			compactionRequests = compactionRequests[1:]
		}
	}
	return 1
}

// A cluster creates files named "127.0.0.1:*" and "localhost:*",
// and these are deleted after each iteration.
func cleanUpDir() {
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
