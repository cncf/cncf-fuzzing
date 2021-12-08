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

package auth

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
)

func init() {
	testing.Init()
}

func FuzzAuthStore(data []byte) int {
	f := fuzz.NewConsumer(data)
	ud := &pb.AuthUserDeleteRequest{}
	err := f.GenerateStruct(ud)
	if err != nil {
		return 0
	}
	ua := &pb.AuthUserAddRequest{}
	err = f.GenerateStruct(ua)
	if err != nil {
		return 0
	}
	cp := &pb.AuthUserChangePasswordRequest{}
	err = f.GenerateStruct(cp)
	if err != nil {
		return 0
	}
	ugr := &pb.AuthUserGrantRoleRequest{}
	err = f.GenerateStruct(ugr)
	if err != nil {
		return 0
	}
	urr := &pb.AuthUserRevokeRoleRequest{}
	err = f.GenerateStruct(urr)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	as, tearDown := setupAuthStore(t)
	defer tearDown(t)

	_, _ = as.UserAdd(ua)
	_, _ = as.UserDelete(ud)
	_, _ = as.UserChangePassword(cp)
	_, _ = as.UserGrantRole(ugr)
	_, _ = as.UserRevokeRole(urr)
	return 1
}
