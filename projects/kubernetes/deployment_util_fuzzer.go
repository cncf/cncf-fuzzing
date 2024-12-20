// Copyright 2022 ADA Logics Ltd
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

package util

import (
	"context"
	apps "k8s.io/api/apps/v1"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/informers"
	"k8s.io/klog/v2"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"time"
)

var (
	functionsToCall = map[int]string {
		0: "FuzzSetDeploymentCondition",
		1: "FuzzRemoveDeploymentCondition",
		2: "FuzzSetDeploymentRevision",
		3: "FuzzMaxAndLastRevision",
		4: "FuzzSetNewReplicaSetAnnotations",
		5: "FuzzSetDeploymentAnnotationsTo",
		6: "FuzzFindActiveOrLatest",
		7: "FuzzGetDesiredReplicasAnnotation",
		8: "FuzzSetReplicasAnnotations",
		9: "FuzzReplicasAnnotationsNeedUpdate",
		10: "FuzzMaxUnavailable", 
		11: "FuzzMinAvailable",
		12: "FuzzMaxSurge",
		13: "FuzzFindNewReplicaSet",
		14: "FuzzFindOldReplicaSets",
		15: "FuzzGetReplicaCountForReplicaSets",
		16: "FuzzGetActualReplicaCountForReplicaSets",
		17: "FuzzGetReadyReplicaCountForReplicaSets",
		18: "FuzzGetAvailableReplicaCountForReplicaSets",
		19: "FuzzNewRSNewReplicas",
		20: "FuzzIsSaturated",
		21: "FuzzResolveFenceposts",
		22: "FuzzGetDeploymentsForReplicaSet", 
	}
)

func FuzzEntireDeploymentUtil(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	functionToCall := int(data[0])
	switch functionsToCall[functionToCall%len(functionsToCall)] {
	case "FuzzSetDeploymentCondition":
		return FuzzSetDeploymentCondition(data[1:])
	case "FuzzRemoveDeploymentCondition":
		return FuzzRemoveDeploymentCondition(data[1:])
	case "FuzzSetDeploymentRevision":
		return FuzzSetDeploymentRevision(data[1:])
	case "FuzzMaxAndLastRevision":
		return FuzzMaxAndLastRevision(data[1:])
	case "FuzzSetNewReplicaSetAnnotations":
		return FuzzSetNewReplicaSetAnnotations(data[1:])
	case "FuzzSetDeploymentAnnotationsTo":
		return FuzzSetDeploymentAnnotationsTo(data[1:])
	case "FuzzFindActiveOrLatest":
		return FuzzFindActiveOrLatest(data[1:])
	case "FuzzGetDesiredReplicasAnnotation":
		return FuzzGetDesiredReplicasAnnotation(data[1:])
	case "FuzzSetReplicasAnnotations":
		return FuzzSetReplicasAnnotations(data[1:])
	case "FuzzReplicasAnnotationsNeedUpdate":
		return FuzzReplicasAnnotationsNeedUpdate(data[1:])
	case "FuzzMaxUnavailable":
		return FuzzMaxUnavailable(data[1:])
	case "FuzzMinAvailable":
		return FuzzMinAvailable(data[1:])
	case "FuzzMaxSurge":
		return FuzzMaxSurge(data[1:])
	case "FuzzFindNewReplicaSet":
		return FuzzFindNewReplicaSet(data[1:])
	case "FuzzFindOldReplicaSets":
		return FuzzFindOldReplicaSets(data[1:])
	case "FuzzGetReplicaCountForReplicaSets":
		return FuzzGetReplicaCountForReplicaSets(data[1:])
	case "FuzzGetActualReplicaCountForReplicaSets":
		return FuzzGetActualReplicaCountForReplicaSets(data[1:])
	case "FuzzGetReadyReplicaCountForReplicaSets":
		return FuzzGetReadyReplicaCountForReplicaSets(data[1:])
	case "FuzzGetAvailableReplicaCountForReplicaSets":
		return FuzzGetAvailableReplicaCountForReplicaSets(data[1:])
	case "FuzzNewRSNewReplicas":
		return FuzzNewRSNewReplicas(data[1:])
	case "FuzzIsSaturated":
		return FuzzIsSaturated(data[1:])
	case "FuzzResolveFenceposts":
		return FuzzResolveFenceposts(data[1:])
	case "FuzzGetDeploymentsForReplicaSet":
		return FuzzGetDeploymentsForReplicaSet(data[1:])
	}
	return 1
}

func FuzzSetDeploymentCondition(data []byte) int {
	// Not supported
	return 1
}

func FuzzRemoveDeploymentCondition(data []byte) int {
	// Not supported
	return 1
}

func FuzzSetDeploymentRevision(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	revision, err := f.GetString()
	if err != nil {
		return 0
	}
	SetDeploymentRevision(deployment, revision)
	return 1
}

func FuzzMaxAndLastRevision(data []byte) int {
	f := fuzz.NewConsumer(data)
	allRSs := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&allRSs)
	if err != nil {
		return 0
	}
	max, err := f.GetBool()
	if err != nil {
		return 0
	}
	logger := klog.Background()
	if max {
		_ = MaxRevision(logger, allRSs)
	} else {
		LastRevision(logger, allRSs)
	}
	return 1
}

func FuzzSetNewReplicaSetAnnotations(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	newRS := &apps.ReplicaSet{}
	err = f.GenerateStruct(newRS)
	if err != nil {
		return 0
	}
	newRevision, err := f.GetString()
	if err != nil {
		return 0
	}
	exists, err := f.GetBool()
	if err != nil {
		return 0
	}
	revHistoryLimitInChars, err := f.GetInt()
	if err != nil {
		return 0
	}
	SetNewReplicaSetAnnotations(context.Background(), deployment, newRS, newRevision, exists, revHistoryLimitInChars)
	return 1
}

func FuzzSetDeploymentAnnotationsTo(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}	
	rollbackToRS := &apps.ReplicaSet{}
	err = f.GenerateStruct(rollbackToRS)
	if err != nil {
		return 0
	}
	SetDeploymentAnnotationsTo(deployment, rollbackToRS)
	return 1
}

func FuzzFindActiveOrLatest(data []byte) int {
	f := fuzz.NewConsumer(data)
	newRS := &apps.ReplicaSet{}
	err := f.GenerateStruct(newRS)
	if err != nil {
		return 0
	}
	oldRSs := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&oldRSs)
	if err != nil {
		return 0
	}
	_ = FindActiveOrLatest(newRS, oldRSs)
	return 1
}

func FuzzGetDesiredReplicasAnnotation(data []byte) int {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return 0
	}
	_, _ = GetDesiredReplicasAnnotation(klog.FromContext(context.Background()), rs)
	return 1
}

func FuzzSetReplicasAnnotations(data []byte) int {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return 0
	}
	desiredReplicas, err := f.GetInt()
	if err != nil {
		return 0
	}
	maxReplicas, err := f.GetInt()
	if err != nil {
		return 0
	}
	SetReplicasAnnotations(rs, int32(desiredReplicas), int32(maxReplicas))
	return 1
}

func FuzzReplicasAnnotationsNeedUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return 0
	}
	desiredReplicas, err := f.GetInt()
	if err != nil {
		return 0
	}
	maxReplicas, err := f.GetInt()
	if err != nil {
		return 0
	}
	ReplicasAnnotationsNeedUpdate(rs, int32(desiredReplicas), int32(maxReplicas))
	return 1
}

func FuzzMaxUnavailable(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := apps.Deployment{}
	err := f.GenerateStruct(&deployment)
	if err != nil {
		return 0
	}
	_ = MaxUnavailable(deployment)
	return 1
}

func FuzzMinAvailable(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	_ = MinAvailable(deployment)
	return 1
}

func FuzzMaxSurge(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := apps.Deployment{}
	err := f.GenerateStruct(&deployment)
	if err != nil {
		return 0
	}
	_ = MaxSurge(deployment)
	return 1
}

func FuzzFindNewReplicaSet(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	rsList := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&rsList)
	if err != nil {
		return 0
	}
	_ = FindNewReplicaSet(deployment, rsList)
	return 1
}

func FuzzFindOldReplicaSets(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	rsList := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&rsList)
	if err != nil {
		return 0
	}
	_, _ = FindOldReplicaSets(deployment, rsList)
	return 1
}

func FuzzGetReplicaCountForReplicaSets(data []byte) int {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return 0
	}
	_ = GetReplicaCountForReplicaSets(replicaSets)
	return 1
}

func FuzzGetActualReplicaCountForReplicaSets(data []byte) int {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return 0
	}
	_ = GetActualReplicaCountForReplicaSets(replicaSets)
	return 1
}

func FuzzGetReadyReplicaCountForReplicaSets(data []byte) int {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return 0
	}
	_ = GetReadyReplicaCountForReplicaSets(replicaSets)
	return 1
}

func FuzzGetAvailableReplicaCountForReplicaSets(data []byte) int {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return 0
	}
	_ = GetAvailableReplicaCountForReplicaSets(replicaSets)
	return 1
}

func FuzzNewRSNewReplicas(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	allRSs := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&allRSs)
	if err != nil {
		return 0
	}
	newRS := &apps.ReplicaSet{}
	err = f.GenerateStruct(newRS)
	if err != nil {
		return 0
	}
	_, _ = NewRSNewReplicas(deployment, allRSs, newRS)
	return 1
}

func FuzzIsSaturated(data []byte) int {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	rs := &apps.ReplicaSet{}
	err = f.GenerateStruct(rs)
	if err != nil {
		return 0
	}
	_ = IsSaturated(deployment, rs)
	return 1
}

func FuzzResolveFenceposts(data []byte) int {
	f := fuzz.NewConsumer(data)
	maxSurge := &intstrutil.IntOrString{}
	err := f.GenerateStruct(maxSurge)
	if err != nil {
		return 0
	}
	maxUnavailable := &intstrutil.IntOrString{}
	err = f.GenerateStruct(maxUnavailable)
	if err != nil {
		return 0
	}
	desired, err := f.GetInt()
	if err != nil {
		return 0
	}
	_, _, _ = ResolveFenceposts(maxSurge, maxUnavailable, int32(desired))
	return 1
}

func FuzzGetDeploymentsForReplicaSet(data []byte) int {
	fakeInformerFactory := informers.NewSharedInformerFactory(&fake.Clientset{}, 0*time.Second)
	
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return 0
	}
	GetDeploymentsForReplicaSet(fakeInformerFactory.Apps().V1().Deployments().Lister(), rs)
	return 1
}
