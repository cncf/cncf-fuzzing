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
	"context"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/zap/zaptest"

	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	membershippb "go.etcd.io/etcd/api/v3/membershippb"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/pkg/v3/wait"
	"go.etcd.io/etcd/raft/v3"
	"go.etcd.io/etcd/raft/v3/raftpb"
	"go.etcd.io/etcd/server/v3/auth"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/etcdserver/api/v2store"
	"go.etcd.io/etcd/server/v3/etcdserver/api/v3alarm"
	"go.etcd.io/etcd/server/v3/etcdserver/cindex"
	"go.etcd.io/etcd/server/v3/lease"
	"go.etcd.io/etcd/server/v3/mock/mockstorage"
	serverstorage "go.etcd.io/etcd/server/v3/storage"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/mvcc"
	"go.etcd.io/etcd/server/v3/storage/schema"

	"go.etcd.io/etcd/pkg/v3/idutil"
	"go.etcd.io/etcd/pkg/v3/notify"
	"go.etcd.io/etcd/server/v3/config"
)

var (
	ab                    applierV3
	tokenTypeSimple       = "simple"
	simpleTokenTTLDefault = 300 * time.Second
	ops                   = map[int]string{
		0:  "Range",
		1:  "Put",
		2:  "DeleteRange",
		3:  "Txn",
		4:  "Compaction",
		5:  "LeaseGrant",
		6:  "LeaseRevoke",
		7:  "Alarm",
		8:  "LeaseCheckpoint",
		9:  "AuthEnable",
		10: "AuthDisable",
		11: "AuthStatus",
		12: "Authenticate",
		13: "AuthUserAdd",
		14: "AuthUserDelete",
		15: "AuthUserGet",
		16: "AuthUserChangePassword",
		17: "AuthUserGrantRole",
		18: "AuthUserRevokeRole",
		19: "AuthUserList",
		20: "AuthRoleList",
		21: "AuthRoleAdd",
		22: "AuthRoleDelete",
		23: "AuthRoleGet",
		24: "AuthRoleGrantPermission",
		25: "AuthRoleRevokePermission",
		26: "ClusterVersionSet",
		27: "ClusterMemberAttrSet",
		28: "DowngradeInfoSet",
	}
	srv *EtcdServer
)

func dummyIndexWaiter(index uint64) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		ch <- struct{}{}
	}()
	return ch
}

func validateRangeRequest(r *pb.RangeRequest) error {
	if r.Key == nil || r.RangeEnd == nil || &r.Limit == nil || &r.Revision == nil || &r.SortOrder == nil || &r.SortTarget == nil || &r.Serializable == nil || &r.KeysOnly == nil || &r.CountOnly == nil || &r.MinModRevision == nil || &r.MaxModRevision == nil {
		return fmt.Errorf("Not valid rangerequest")
	}
	return nil
}

func validatePutRequest(r *pb.PutRequest) error {
	if r.Key == nil || r.Value == nil || &r.Lease == nil || &r.PrevKv == nil || &r.IgnoreValue == nil || &r.IgnoreLease == nil {
		return fmt.Errorf("Not valid putrequest")
	}
	return nil
}

func validateDeleteRangeRequest(r *pb.DeleteRangeRequest) error {
	if r.Key == nil || r.RangeEnd == nil || &r.PrevKv == nil {
		return fmt.Errorf("Not valid DeleteRangeRequest")
	}
	return nil
}

func validateTxnRequest(r *pb.TxnRequest) error {
	if r.Compare == nil || r.Success == nil || r.Failure == nil {
		return fmt.Errorf("Not valid TxnRequest")
	}
	return nil
}

func validateCompactionRequest(r *pb.CompactionRequest) error {
	if &r.Revision == nil || &r.Physical == nil {
		return fmt.Errorf("Not valid CompactionRequest ")
	}
	return nil
}

func validateLeaseGrantRequest(r *pb.LeaseGrantRequest) error {
	if &r.TTL == nil || &r.ID == nil {
		return fmt.Errorf("Not valid LeaseGrantRequest")
	}
	return nil
}

func validateLeaseRevokeRequest(r *pb.LeaseRevokeRequest) error {
	if &r.ID == nil {
		return fmt.Errorf("Not valid LeaseRevokeRequest")
	}
	return fmt.Errorf("")
	return nil
}

func validateAlarmRequest(r *pb.AlarmRequest) error {
	if &r.Action == nil || &r.MemberID == nil || &r.Alarm == nil {
		return fmt.Errorf("Not valid AlarmRequest")
	}
	return nil
}

func validateLeaseCheckpointRequest(r *pb.LeaseCheckpointRequest) error {
	if r.Checkpoints == nil {
		return fmt.Errorf("Not valid LeaseCheckpointRequest")
	}
	return nil
}

func validateAuthEnableRequest(r *pb.AuthEnableRequest) error {
	return nil
}

func validateAuthDisableRequest(r *pb.AuthDisableRequest) error {
	return nil
}

func validateAuthStatusRequest(r *pb.AuthStatusRequest) error {
	return nil
}

func validateInternalAuthenticateRequest(r *pb.InternalAuthenticateRequest) error {
	if &r.Name == nil || &r.Password == nil || &r.SimpleToken == nil {
		return fmt.Errorf("Not a valid InternalAuthenticateRequest")
	}
	return nil
}

func validateAuthUserAddRequest(r *pb.AuthUserAddRequest) error {
	if &r.Name == nil || &r.Password == nil || &r.Options == nil || &r.HashedPassword == nil {
		return fmt.Errorf("Not a valid AuthUserAddRequest")
	}
	return nil
}

func validateAuthUserDeleteRequest(r *pb.AuthUserDeleteRequest) error {
	if &r.Name == nil {
		return fmt.Errorf("Not a valid AuthUserDeleteRequest")
	}
	return nil
}

func validateAuthUserGetRequest(r *pb.AuthUserGetRequest) error {
	if &r.Name == nil {
		return fmt.Errorf("Not a valid AuthUserGetRequest")
	}
	return nil
}

func validateAuthUserChangePasswordRequest(r *pb.AuthUserChangePasswordRequest) error {
	if &r.Name == nil || &r.Password == nil || &r.HashedPassword == nil {
		return fmt.Errorf("Not a valid AuthUserChangePasswordRequest")
	}
	return nil
}

func validateAuthUserGrantRoleRequest(r *pb.AuthUserGrantRoleRequest) error {
	if &r.User == nil || &r.Role == nil {
		return fmt.Errorf("Not a valid AuthUserGrantRoleRequest")
	}
	return nil
}

func validateAuthUserRevokeRoleRequest(r *pb.AuthUserRevokeRoleRequest) error {
	if &r.Name == nil || &r.Role == nil {
		return fmt.Errorf("Not a valid AuthUserRevokeRoleRequest")
	}
	return nil
}

func validateAuthUserListRequest(r *pb.AuthUserListRequest) error {
	return nil
}

func validateAuthRoleListRequest(r *pb.AuthRoleListRequest) error {
	return nil
}

func validateAuthRoleAddRequest(r *pb.AuthRoleAddRequest) error {
	if &r.Name == nil {
		return fmt.Errorf("Not a valid AuthRoleAddRequest")
	}
	return nil
}

func validateAuthRoleDeleteRequest(r *pb.AuthRoleDeleteRequest) error {
	if &r.Role == nil {
		return fmt.Errorf("Not a valid AuthRoleDeleteRequest")
	}
	return nil
}

func validateAuthRoleGetRequest(r *pb.AuthRoleGetRequest) error {
	if &r.Role == nil {
		return fmt.Errorf("Not a valid AuthRoleGetRequest")
	}
	return nil
}

func validateAuthRoleGrantPermissionRequest(r *pb.AuthRoleGrantPermissionRequest) error {
	if &r.Name == nil || &r.Perm == nil {
		return fmt.Errorf("Not a valid AuthRoleGrantPermissionRequest")
	}
	return nil
}

func validateAuthRoleRevokePermissionRequest(r *pb.AuthRoleRevokePermissionRequest) error {
	if &r.Role == nil || &r.Key == nil || &r.RangeEnd == nil {
		return fmt.Errorf("Not a valid AuthRoleRevokePermissionRequest")
	}
	return nil
}

func validateClusterVersionSetRequest(r *membershippb.ClusterVersionSetRequest) error {
	if &r.Ver == nil {
		return fmt.Errorf("Not a valid ClusterVersionSetRequest")
	}
	return nil
}

func validateClusterMemberAttrSetRequest(r *membershippb.ClusterMemberAttrSetRequest) error {
	if &r.Member_ID == nil || &r.MemberAttributes == nil {
		return fmt.Errorf("Not a valid ClusterMemberAttrSetRequest")
	}
	return nil
}

func validateDowngradeInfoSetRequest(r *membershippb.DowngradeInfoSetRequest) error {
	if &r.Enabled == nil || &r.Ver == nil {
		return fmt.Errorf("Not a valid DowngradeInfoSetRequest")
	}
	return nil
}

func setRequestType(internalRequest *pb.InternalRaftRequest, f *fuzz.ConsumeFuzzer) error {
	opInt, err := f.GetInt()
	if err != nil {
		return err
	}
	opType := ops[opInt%len(ops)]
	switch opType {
	case "Range":
		r := &pb.RangeRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateRangeRequest(r)
		if err != nil {
			return err
		}
		internalRequest.Range = r
	case "Put":
		r := &pb.PutRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validatePutRequest(r)
		if err != nil {
			return err
		}
		internalRequest.Put = r
	case "DeleteRange":
		r := &pb.DeleteRangeRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateDeleteRangeRequest(r)
		if err != nil {
			return err
		}
		internalRequest.DeleteRange = r
	case "Txn":
		r := &pb.TxnRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateTxnRequest(r)
		if err != nil {
			return err
		}
		internalRequest.Txn = r
	case "Compaction":
		r := &pb.CompactionRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateCompactionRequest(r)
		if err != nil {
			return err
		}
		internalRequest.Compaction = r
	case "LeaseGrant":
		r := &pb.LeaseGrantRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateLeaseGrantRequest(r)
		if err != nil {
			return err
		}
		internalRequest.LeaseGrant = r
	case "LeaseRevoke":
		r := &pb.LeaseRevokeRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateLeaseRevokeRequest(r)
		if err != nil {
			return err
		}
		internalRequest.LeaseRevoke = r
	case "Alarm":
		r := &pb.AlarmRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		internalRequest.Alarm = r
	case "LeaseCheckpoint":
		r := &pb.LeaseCheckpointRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateLeaseCheckpointRequest(r)
		if err != nil {
			return err
		}
		internalRequest.LeaseCheckpoint = r
	case "AuthEnable":
		r := &pb.AuthEnableRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthEnableRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthEnable = r
	case "AuthDisable":
		r := &pb.AuthDisableRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthDisableRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthDisable = r
	case "AuthStatus":
		r := &pb.AuthStatusRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthStatusRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthStatus = r
	case "Authenticate":
		r := &pb.InternalAuthenticateRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateInternalAuthenticateRequest(r)
		if err != nil {
			return err
		}
		internalRequest.Authenticate = r
	case "AuthUserAdd":
		r := &pb.AuthUserAddRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserAddRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserAdd = r
	case "AuthUserDelete":
		r := &pb.AuthUserDeleteRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserDeleteRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserDelete = r
	case "AuthUserGet":
		r := &pb.AuthUserGetRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserGetRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserGet = r
	case "AuthUserChangePassword":
		r := &pb.AuthUserChangePasswordRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserChangePasswordRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserChangePassword = r
	case "AuthUserGrantRole":
		r := &pb.AuthUserGrantRoleRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserGrantRoleRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserGrantRole = r
	case "AuthUserRevokeRole":
		r := &pb.AuthUserRevokeRoleRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserRevokeRoleRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserRevokeRole = r
	case "AuthUserList":
		r := &pb.AuthUserListRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthUserListRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthUserList = r
	case "AuthRoleList":
		r := &pb.AuthRoleListRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthRoleListRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthRoleList = r
	case "AuthRoleAdd":
		r := &pb.AuthRoleAddRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthRoleAddRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthRoleAdd = r
	case "AuthRoleDelete":
		r := &pb.AuthRoleDeleteRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthRoleDeleteRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthRoleDelete = r
	case "AuthRoleGet":
		r := &pb.AuthRoleGetRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthRoleGetRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthRoleGet = r
	case "AuthRoleGrantPermission":
		r := &pb.AuthRoleGrantPermissionRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthRoleGrantPermissionRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthRoleGrantPermission = r
	case "AuthRoleRevokePermission":
		r := &pb.AuthRoleRevokePermissionRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateAuthRoleRevokePermissionRequest(r)
		if err != nil {
			return err
		}
		internalRequest.AuthRoleRevokePermission = r
	case "ClusterVersionSet":
		r := &membershippb.ClusterVersionSetRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateClusterVersionSetRequest(r)
		if err != nil {
			return err
		}
		internalRequest.ClusterVersionSet = r
	case "ClusterMemberAttrSet":
		r := &membershippb.ClusterMemberAttrSetRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateClusterMemberAttrSetRequest(r)
		if err != nil {
			return err
		}
		internalRequest.ClusterMemberAttrSet = r
	case "DowngradeInfoSet":
		r := &membershippb.DowngradeInfoSetRequest{}
		err := f.GenerateStruct(r)
		if err != nil {
			return err
		}
		err = validateDowngradeInfoSetRequest(r)
		if err != nil {
			return err
		}
		internalRequest.DowngradeInfoSet = r
	}
	return nil
}

func init() {
	testing.Init()
	t := &testing.T{}
	lg := zaptest.NewLogger(t, zaptest.Level(zapcore.FatalLevel))

	cl := membership.NewCluster(lg)
	cl.SetStore(v2store.New())
	cl.AddMember(&membership.Member{ID: types.ID(1)}, true)

	be, _ := betesting.NewDefaultTmpBackend(t)
	//defer betesting.Close(t, be)

	schema.CreateMetaBucket(be.BatchTx())

	ci := cindex.NewConsistentIndex(be)
	tp, err := auth.NewTokenProvider(zap.NewExample(), tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	if err != nil {
		panic(err)
	}

	srv = &EtcdServer{
		be:           be,
		lgMu:         new(sync.RWMutex),
		lg:           lg,
		id:           1,
		r:            *newRaftNodeForFuzzing(lg),
		cluster:      cl,
		w:            wait.New(),
		consistIndex: ci,
		beHooks:      serverstorage.NewBackendHooks(lg, ci),
		authStore:    auth.NewAuthStore(zap.NewExample(), schema.NewAuthBackend(lg, be), tp, 0),
		SyncTicker:   &time.Ticker{},
	}
	srv.kv = mvcc.New(zap.NewExample(), be, &lease.FakeLessor{}, mvcc.StoreConfig{})

	le := lease.NewLessor(lg, be, srv.cluster, lease.LessorConfig{MinLeaseTTL: int64(5)})

	//srv.lessor = &lease.FakeLessor{}
	srv.lessor = le
	alarmStore, err := v3alarm.NewAlarmStore(srv.lg, schema.NewAlarmBackend(srv.lg, srv.be))
	if err != nil {
		panic(err)
	}
	srv.alarmStore = alarmStore
	srv.be = be
	srv.applyV3Internal = srv.newApplierV3Internal()
	srv.applyV3 = srv.newApplierV3()
	ab = srv.newApplierV3Backend()

	srv.r.start(&raftReadyHandler{
		getLead:          func() uint64 { return 0 },
		updateLead:       func(uint64) {},
		updateLeadership: func(bool) {},
	})

	srv.start()
}

func newRaftNodeForFuzzing(lg *zap.Logger) *raftNode {
	storage := raft.NewMemoryStorage()
	rs := raft.NewMemoryStorage()
	storage.SetHardState(raftpb.HardState{Commit: 0, Term: 0})
	c := &raft.Config{
		ID:              1,
		ElectionTick:    10,
		HeartbeatTick:   1,
		Storage:         storage,
		MaxSizePerMsg:   math.MaxUint64,
		MaxInflightMsgs: 256,
	}
	n := raft.RestartNode(c)
	r := newRaftNode(raftNodeConfig{
		lg:          lg,
		Node:        n,
		transport:   newNopTransporter(),
		raftStorage: rs,
		storage:     mockstorage.NewStorageRecorder(""),
	})
	return r
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
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "unknown entry type; must be either EntryNormal or EntryConfChange") {
			return
		} else if strings.Contains(err, "should never fail") {
			return
		} else if strings.Contains(err, "failed to unmarshal confChangeContext") {
			return
		} else if strings.Contains(err, "unknown ConfChange type") {
			return
		} else if strings.Contains(err, "applyEntryNormal, could not find a header") {
			return
		} else {
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

func catchPanics2() {
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
		if strings.Contains(err, "is not in dotted-tri format") {
			return
		} else if strings.Contains(err, "strconv.ParseInt: parsing") {
			return
		} else if strings.Contains(err, "is not a valid semver identifier") {
			return
		} else if strings.Contains(err, "invalid downgrade; server version is lower than determined cluster version") {
			return
		} else if strings.Contains(err, "unexpected sort target") {
			return
		} else if strings.Contains(err, "failed to unmarshal 'authpb.User'") {
			return
		} else if strings.Contains(err, "unimplemented alarm activation") {
			return
		} else if strings.Contains(err, "failed to update; member unknown") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzapplierV3backendApply(data []byte) int {
	defer catchPanics2()
	f := fuzz.NewConsumer(data)
	rr := &pb.InternalRaftRequest{}
	err := setRequestType(rr, f)
	if err != nil {
		return 0
	}
	_ = ab.Apply(rr, true)
	return 1
}

var (
	pr     []*pb.PutRequest
	drr    []*pb.DeleteRangeRequest
	tr     []*pb.TxnRequest
	cr     []*pb.CompactionRequest
	lgr    []*pb.LeaseGrantRequest
	lrr    []*pb.LeaseRevokeRequest
	ar     []*pb.AlarmRequest
	lcr    []*pb.LeaseCheckpointRequest
	aer    []*pb.AuthEnableRequest
	adr    []*pb.AuthDisableRequest
	asr    []*pb.AuthStatusRequest
	iar    []*pb.InternalAuthenticateRequest
	auar   []*pb.AuthUserAddRequest
	audr   []*pb.AuthUserDeleteRequest
	augr   []*pb.AuthUserGetRequest
	aucpr  []*pb.AuthUserChangePasswordRequest
	augrr  []*pb.AuthUserGrantRoleRequest
	aurrr  []*pb.AuthUserRevokeRoleRequest
	aulr   []*pb.AuthUserListRequest
	arlr   []*pb.AuthRoleListRequest
	arar   []*pb.AuthRoleAddRequest
	ardr   []*pb.AuthRoleDeleteRequest
	argr   []*pb.AuthRoleGetRequest
	argpr  []*pb.AuthRoleGrantPermissionRequest
	arrpr  []*pb.AuthRoleRevokePermissionRequest
	v3reqs = map[int]string{
		0:  "PutRequest",
		1:  "DeleteRangeRequest",
		2:  "TxnRequest",
		3:  "CompactionRequest",
		4:  "LeaseGrantRequest",
		5:  "LeaseRevokeRequest",
		6:  "AlarmRequest",
		7:  "LeaseCheckpointRequest",
		8:  "AuthEnableRequest",
		9:  "AuthDisableRequest",
		10: "InternalAuthenticateRequest",
		11: "AuthUserAddRequest",
		12: "AuthUserDeleteRequest",
		13: "AuthUserGetRequest",
		14: "AuthUserChangePasswordRequest",
		15: "AuthUserGrantRoleRequest",
		16: "AuthUserRevokeRoleRequest",
		17: "AuthUserListRequest",
		18: "AuthRoleListRequest",
		19: "AuthRoleAddRequest",
		20: "AuthRoleDeleteRequest",
		21: "AuthRoleGetRequest",
		22: "AuthRoleGrantPermissionRequest",
		23: "AuthRoleRevokePermissionRequest",
	}
	createdRequests []string
)

func initFuncV3ServerFuzer() {
	pr = make([]*pb.PutRequest, 0)
	drr = make([]*pb.DeleteRangeRequest, 0)
	tr = make([]*pb.TxnRequest, 0)
	cr = make([]*pb.CompactionRequest, 0)
	lgr = make([]*pb.LeaseGrantRequest, 0)
	lrr = make([]*pb.LeaseRevokeRequest, 0)
	ar = make([]*pb.AlarmRequest, 0)
	lcr = make([]*pb.LeaseCheckpointRequest, 0)
	aer = make([]*pb.AuthEnableRequest, 0)
	adr = make([]*pb.AuthDisableRequest, 0)
	asr = make([]*pb.AuthStatusRequest, 0)
	iar = make([]*pb.InternalAuthenticateRequest, 0)
	auar = make([]*pb.AuthUserAddRequest, 0)
	audr = make([]*pb.AuthUserDeleteRequest, 0)
	augr = make([]*pb.AuthUserGetRequest, 0)
	aucpr = make([]*pb.AuthUserChangePasswordRequest, 0)
	augrr = make([]*pb.AuthUserGrantRoleRequest, 0)
	aurrr = make([]*pb.AuthUserRevokeRoleRequest, 0)
	aulr = make([]*pb.AuthUserListRequest, 0)
	arlr = make([]*pb.AuthRoleListRequest, 0)
	arar = make([]*pb.AuthRoleAddRequest, 0)
	ardr = make([]*pb.AuthRoleDeleteRequest, 0)
	argr = make([]*pb.AuthRoleGetRequest, 0)
	argpr = make([]*pb.AuthRoleGrantPermissionRequest, 0)
	arrpr = make([]*pb.AuthRoleRevokePermissionRequest, 0)
	createdRequests = make([]string, 0)
}

func createRequestsV3ServerFuzzer(data []byte) error {
	f := fuzz.NewConsumer(data)
	noOfRequests, err := f.GetInt()
	if err != nil {
		return err
	}
	for i := 0; i < noOfRequests%20; i++ {
		reqType, err := f.GetInt()
		if err != nil {
			return err
		}
		reqTypeStr := v3reqs[reqType%len(v3reqs)]
		switch reqTypeStr {
		case "PutRequest":
			r := &pb.PutRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			pr = append(pr, r)
		case "DeleteRangeRequest":
			r := &pb.DeleteRangeRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			drr = append(drr)
		case "TxnRequest":
			r := &pb.TxnRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			tr = append(tr, r)
		case "CompactionRequest":
			r := &pb.CompactionRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			cr = append(cr, r)
		case "LeaseGrantRequest":
			r := &pb.LeaseGrantRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			lgr = append(lgr, r)
		case "LeaseRevokeRequest":
			r := &pb.LeaseRevokeRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			lrr = append(lrr, r)
		case "AlarmRequest":
			r := &pb.AlarmRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			ar = append(ar, r)
		case "LeaseCheckpointRequest":
			r := &pb.LeaseCheckpointRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			lcr = append(lcr, r)
		case "AuthEnableRequest":
			r := &pb.AuthEnableRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			aer = append(aer, r)
		case "AuthDisableRequest":
			r := &pb.AuthDisableRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			adr = append(adr, r)
		case "InternalAuthenticateRequest":
			r := &pb.InternalAuthenticateRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			iar = append(iar, r)
		case "AuthUserAddRequest":
			r := &pb.AuthUserAddRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			auar = append(auar, r)
		case "AuthUserDeleteRequest":
			r := &pb.AuthUserDeleteRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			audr = append(audr, r)
		case "AuthUserGetRequest":
			r := &pb.AuthUserGetRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			augr = append(augr)
		case "AuthUserChangePasswordRequest":
			r := &pb.AuthUserChangePasswordRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			aucpr = append(aucpr, r)
		case "AuthUserGrantRoleRequest":
			r := &pb.AuthUserGrantRoleRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			augrr = append(augrr, r)
		case "AuthUserRevokeRoleRequest":
			r := &pb.AuthUserRevokeRoleRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			aurrr = append(aurrr, r)
		case "AuthUserListRequest":
			r := &pb.AuthUserListRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			aulr = append(aulr, r)
		case "AuthRoleListRequest":
			r := &pb.AuthRoleListRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			arlr = append(arlr, r)
		case "AuthRoleAddRequest":
			r := &pb.AuthRoleAddRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			arar = append(arar, r)
		case "AuthRoleDeleteRequest":
			r := &pb.AuthRoleDeleteRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			ardr = append(ardr, r)
		case "AuthRoleGetRequest":
			r := &pb.AuthRoleGetRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			argr = append(argr, r)
		case "AuthRoleGrantPermissionRequest":
			r := &pb.AuthRoleGrantPermissionRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			argpr = append(argpr, r)
		case "AuthRoleRevokePermissionRequest":
			r := &pb.AuthRoleRevokePermissionRequest{}
			err = f.GenerateStruct(r)
			if err != nil {
				return err
			}
			arrpr = append(arrpr, r)
		}
		createdRequests = append(createdRequests, reqTypeStr)
	}
	return nil
}

func makeV3Requests(s *EtcdServer) {
	for _, reqType := range createdRequests {
		switch reqType {
		case "PutRequest":
			if len(pr) == 0 {
				return
			}
			r := pr[0]
			_, _ = s.Put(context.Background(), r)
			pr = pr[1:]
		case "DeleteRangeRequest":
			if len(drr) == 0 {
				return
			}
			r := drr[0]
			_, _ = s.DeleteRange(context.Background(), r)
			drr = drr[1:]
		case "TxnRequest":
			if len(tr) == 0 {
				return
			}
			r := tr[0]
			_, _ = s.Txn(context.Background(), r)
			tr = tr[1:]
		case "CompactionRequest":
			if len(cr) == 0 {
				return
			}
			r := cr[0]
			_, _ = s.Compact(context.Background(), r)
			cr = cr[1:]
		case "LeaseGrantRequest":
			if len(lgr) == 0 {
				return
			}
			r := lgr[0]
			_, _ = s.LeaseGrant(context.Background(), r)
			lgr = lgr[1:]
		case "LeaseRevokeRequest":
			if len(lrr) == 0 {
				return
			}
			r := lrr[0]
			_, _ = s.LeaseRevoke(context.Background(), r)
			lrr = lrr[1:]
		case "AlarmRequest":
			if len(ar) == 0 {
				return
			}
			r := ar[0]
			_, _ = s.Alarm(context.Background(), r)
			ar = ar[1:]
		case "LeaseCheckpointRequest":
			return
		case "AuthEnableRequest":
			if len(aer) == 0 {
				return
			}
			r := aer[0]
			_, _ = s.AuthEnable(context.Background(), r)
			aer = aer[1:]
		case "AuthDisableRequest":
			if len(adr) == 0 {
				return
			}
			r := adr[0]
			_, _ = s.AuthDisable(context.Background(), r)
			adr = adr[1:]
		case "InternalAuthenticateRequest":
			return
		case "AuthUserAddRequest":
			if len(auar) == 0 {
				return
			}
			r := auar[0]
			_, _ = s.UserAdd(context.Background(), r)
			auar = auar[1:]
		case "AuthUserDeleteRequest":
			if len(audr) == 0 {
				return
			}
			r := audr[0]
			_, _ = s.UserDelete(context.Background(), r)
			audr = audr[1:]
		case "AuthUserGetRequest":
			if len(augr) == 0 {
				return
			}
			r := augr[0]
			_, _ = s.UserGet(context.Background(), r)
			augr = augr[1:]
		case "AuthUserChangePasswordRequest":
			if len(aucpr) == 0 {
				return
			}
			r := aucpr[0]
			_, _ = s.UserChangePassword(context.Background(), r)
			aucpr = aucpr[1:]
		case "AuthUserGrantRoleRequest":
			if len(augrr) == 0 {
				return
			}
			r := augrr[0]
			_, _ = s.UserGrantRole(context.Background(), r)
			augrr = augrr[1:]
		case "AuthUserRevokeRoleRequest":
			if len(aurrr) == 0 {
				return
			}
			r := aurrr[0]
			_, _ = s.UserRevokeRole(context.Background(), r)
			aurrr = aurrr[1:]
		case "AuthUserListRequest":
			if len(aulr) == 0 {
				return
			}
			r := aulr[0]
			_, _ = s.UserList(context.Background(), r)
			aulr = aulr[1:]
		case "AuthRoleListRequest":
			if len(arlr) == 0 {
				return
			}
			r := arlr[0]
			_, _ = s.RoleList(context.Background(), r)
			arlr = arlr[1:]
		case "AuthRoleAddRequest":
			if len(arar) == 0 {
				return
			}
			r := arar[0]
			_, _ = s.RoleAdd(context.Background(), r)
			arar = arar[1:]
		case "AuthRoleDeleteRequest":
			if len(ardr) == 0 {
				return
			}
			r := ardr[0]
			_, _ = s.RoleDelete(context.Background(), r)
			ardr = ardr[1:]
		case "AuthRoleGetRequest":
			if len(argr) == 0 {
				return
			}
			r := argr[0]
			_, _ = s.RoleGet(context.Background(), r)
			argr = argr[1:]
		case "AuthRoleGrantPermissionRequest":
			if len(argpr) == 0 {
				return
			}
			r := argpr[0]
			_, _ = s.RoleGrantPermission(context.Background(), r)
			argpr = argpr[1:]
		case "AuthRoleRevokePermissionRequest":
			if len(arrpr) == 0 {
				return
			}
			r := arrpr[0]
			_, _ = s.RoleRevokePermission(context.Background(), r)
			arrpr = arrpr[1:]
		}
	}
}

func FuzzV3Server(data []byte) int {
	initFuncV3ServerFuzer()
	err := createRequestsV3ServerFuzzer(data)
	if err != nil {
		return 0
	}
	if len(createdRequests) < 2 {
		return 0
	}
	defer catchPanics()

	// Setup server
	t := &testing.T{}
	lg := zaptest.NewLogger(t, zaptest.Level(zapcore.FatalLevel))

	cl := membership.NewCluster(zaptest.NewLogger(t))
	cl.SetStore(v2store.New())
	cl.AddMember(&membership.Member{ID: types.ID(1)}, true)

	be, _ := betesting.NewDefaultTmpBackend(t)
	defer betesting.Close(t, be)

	schema.CreateMetaBucket(be.BatchTx())

	st := make(chan time.Time, 1)
	tk := &time.Ticker{C: st}
	tk = time.NewTicker(500 * time.Millisecond)

	ci := cindex.NewConsistentIndex(be)
	tp, err := auth.NewTokenProvider(lg, tokenTypeSimple, dummyIndexWaiter, simpleTokenTTLDefault)
	srv := &EtcdServer{
		lgMu:                  new(sync.RWMutex),
		lg:                    lg,
		id:                    1,
		r:                     *newRaftNodeForFuzzing(lg),
		cluster:               cl,
		w:                     wait.New(),
		consistIndex:          ci,
		beHooks:               serverstorage.NewBackendHooks(lg, ci),
		reqIDGen:              idutil.NewGenerator(0, time.Time{}),
		firstCommitInTerm:     notify.NewNotifier(),
		clusterVersionChanged: notify.NewNotifier(),
		SyncTicker:            tk,
		authStore:             auth.NewAuthStore(lg, schema.NewAuthBackend(lg, be), tp, 0),
		Cfg:                   config.ServerConfig{ElectionTicks: 10, Logger: lg, TickMs: 10000, SnapshotCatchUpEntries: DefaultSnapshotCatchUpEntries, MaxRequestBytes: 10000},
	}
	srv.applyV3Base = srv.newApplierV3Backend()
	srv.kv = mvcc.New(lg, be, &lease.FakeLessor{}, mvcc.StoreConfig{})

	srv.Start()
	defer srv.Stop()
	makeV3Requests(srv)
	return 1
}
