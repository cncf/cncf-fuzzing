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

package raft

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	pb "go.etcd.io/etcd/raft/v3/raftpb"
)

func FuzzNetworkSend(data []byte) int {
	f := fuzz.NewConsumer(data)
	msg := pb.Message{}
	err := f.GenerateStruct(&msg)
	if err != nil {
		return 0
	}

	n1 := newTestLearnerRaft(1, 10, 1, newTestMemoryStorage(withPeers(1), withLearners(2)))
	n2 := newTestLearnerRaft(2, 10, 1, newTestMemoryStorage(withPeers(1), withLearners(2)))

	nt := newNetwork(n1, n2)

	n1.becomeFollower(1, None)
	n2.becomeFollower(1, None)

	setRandomizedElectionTimeout(n1, n1.electionTimeout)
	for i := 0; i < n1.electionTimeout; i++ {
		n1.tick()
	}

	nt.send(msg)
	return 1
}

func FuzzStep(data []byte) int {
	f := fuzz.NewConsumer(data)
	msg := pb.Message{}
	err := f.GenerateStruct(&msg)
	if err != nil {
		return 0
	}
	r := newTestRaft(1, 5, 1, newTestMemoryStorage(withPeers(1, 2)))
	r.becomeCandidate()
	r.becomeLeader()
	r.prs.Progress[2].BecomeReplicate()
	_ = r.Step(msg)
	_ = r.readMessages()
	return 1
}
