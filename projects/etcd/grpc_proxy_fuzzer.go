/*
remove the "Short" testing thing in etcd/client/pkg/testutil/testutil.go
*/
package fuzzing

import (
	"context"
	"fmt"
	"testing"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/proxy/grpcproxy"
	integration2 "go.etcd.io/etcd/tests/v3/framework/integration"
)

var (
	t1 = &testing.T{}

	// numberOfExecs is the number of executions inbetween
	// new initializations.
	numberOfExecs int

	// payloads is a slice of payloads. It is reset everytime
	// "resetAfterExecs" is reset. This is kept for reproduceability.
	payloads [][]byte

	clus   *integration2.ClusterV3
	cfg    clientv3.Config
	client *clientv3.Client
	kvp    pb.KVServer
)

func init() {
	testing.Init()
	integration2.BeforeTest(t1)

	numberOfExecs = 0
	clus = integration2.NewClusterV3(t1, &integration2.ClusterConfig{Size: 1})
	payloads = make([][]byte, 0)
	cfg = clientv3.Config{
		Endpoints:   []string{clus.Members[0].GRPCURL()},
		DialTimeout: 5 * time.Second,
	}
	client, err := integration2.NewClient(t1, cfg)
	if err != nil {
		panic(err)
	}
	kvp, _ = grpcproxy.NewKvProxy(client)
}

func checkAndDoReset() {
	if numberOfExecs == 50000 {
		clus.Terminate(t1)
		clus = integration2.NewClusterV3(t1, &integration2.ClusterConfig{Size: 1})
		payloads = make([][]byte, 0)
		cfg = clientv3.Config{
			Endpoints:   []string{clus.Members[0].GRPCURL()},
			DialTimeout: 5 * time.Second,
		}
		client, err := integration2.NewClient(t1, cfg)
		if err != nil {
			panic(err)
		}
		kvp, _ = grpcproxy.NewKvProxy(client)
	}
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

func FuzzKVProxy(data []byte) int {
	checkAndDoReset()
	f := fuzz.NewConsumer(data)
	rr := &pb.RangeRequest{}
	err := f.GenerateStruct(rr)
	if err != nil {
		return 0
	}
	err = validateRangeRequest(rr)
	if err != nil {
		return 0
	}
	pr := &pb.PutRequest{}
	err = f.GenerateStruct(pr)
	if err != nil {
		return 0
	}
	err = validatePutRequest(pr)
	if err != nil {
		return 0
	}
	dr := &pb.DeleteRangeRequest{}
	err = f.GenerateStruct(dr)
	if err != nil {
		return 0
	}
	err = validateDeleteRangeRequest(dr)
	if err != nil {
		return 0
	}
	// since we now know that the fuzzer has created valid bytes
	// for both the RangeRequest, the PutRequest, the DeleteRangeRequest,
	// the bytes can be added and we can count a valid execution.
	numberOfExecs++
	payloads = append(payloads, data)

	_, _ = kvp.Range(context.Background(), rr)
	_, _ = kvp.Put(context.Background(), pr)
	_, _ = kvp.DeleteRange(context.Background(), dr)
	return 1
}
