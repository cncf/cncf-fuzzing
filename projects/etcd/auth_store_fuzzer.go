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

package auth

import (
	"context"
	"encoding/base64"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"golang.org/x/crypto/bcrypt"

	"go.etcd.io/etcd/api/v3/authpb"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
)

var opTypes = map[int]string{
	0:  "CheckPassword",
	1:  "UserDelete",
	2:  "Authenticate",
	3:  "UserChangePassword",
	4:  "UserGrantRole",
	5:  "HasRole",
	6:  "RoleGrantPermission",
	7:  "UserGet",
	8:  "UserList",
	9:  "RoleGet",
	10: "RoleRevokePermission",
	11: "RoleDelete",
	12: "IsAdminPermitted",
}

func encodePasswordFuzz(s string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	return base64.StdEncoding.EncodeToString([]byte(hashedPassword))
}

func usernameAndPassword(f *fuzz.ConsumeFuzzer) (string, string, error) {
	username, err := f.GetString()
	if err != nil {
		return "", "", err
	}
	password, err := f.GetString()
	if err != nil {
		return "", "", err
	}
	return username, encodePasswordFuzz(password), nil
}

func getNewUser(f *fuzz.ConsumeFuzzer) (*pb.AuthUserAddRequest, error) {
	newUser := &pb.AuthUserAddRequest{}
	username, hashedPassword, err := usernameAndPassword(f)
	if err != nil {
		return nil, err
	}
	newUser.Name = username
	newUser.HashedPassword = hashedPassword
	options := &authpb.UserAddOptions{}
	err = f.GenerateStruct(options)
	if err != nil {
		return nil, err
	}
	return newUser, nil
}

func createUserList(f *fuzz.ConsumeFuzzer) ([]*pb.AuthUserAddRequest, error) {
	noOfUsers, err := f.GetInt()
	if err != nil {
		return nil, err
	}
	userList := make([]*pb.AuthUserAddRequest, 0)
	for i := 0; i < noOfUsers%30; i++ {
		newUser, err := getNewUser(f)
		if err != nil {
			return nil, err
		}
		userList = append(userList, newUser)
	}
	return userList, nil
}

func createUserRoleList(f *fuzz.ConsumeFuzzer) ([]*pb.AuthRoleAddRequest, error) {
	noOfRoles, err := f.GetInt()
	if err != nil {
		return nil, err
	}
	userRoleList := make([]*pb.AuthRoleAddRequest, 0)
	for i := 0; i < noOfRoles%30; i++ {
		newRole := &pb.AuthRoleAddRequest{}
		roleName, err := f.GetString()
		if err != nil {
			return nil, err
		}
		newRole.Name = roleName
		userRoleList = append(userRoleList, newRole)
	}
	return userRoleList, nil
}

func deleteUser(f *fuzz.ConsumeFuzzer, as *authStore) error {
	username, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = as.UserDelete(&pb.AuthUserDeleteRequest{Name: username})
	return nil
}

func checkPassword(f *fuzz.ConsumeFuzzer, as *authStore) error {
	username, err := f.GetString()
	if err != nil {
		return err
	}
	password, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = as.CheckPassword(username, password)
	return nil
}

func roleGet(f *fuzz.ConsumeFuzzer, as *authStore) error {
	role, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = as.RoleGet(&pb.AuthRoleGetRequest{Role: role})
	return nil
}

func roleDelete(f *fuzz.ConsumeFuzzer, as *authStore) error {
	role, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = as.RoleDelete(&pb.AuthRoleDeleteRequest{Role: role})
	return nil
}

func isAdminPermitted(f *fuzz.ConsumeFuzzer, as *authStore) error {
	r := &AuthInfo{}
	err := f.GenerateStruct(r)
	if err != nil {
		return err
	}
	_ = as.IsAdminPermitted(r)
	return nil
}

func roleRevokePermission(f *fuzz.ConsumeFuzzer, as *authStore) error {
	r := &pb.AuthRoleRevokePermissionRequest{}
	err := f.GenerateStruct(r)
	if err != nil {
		return err
	}
	_, _ = as.RoleRevokePermission(r)
	return nil
}

func userChangePassword(f *fuzz.ConsumeFuzzer, as *authStore) error {
	r := &pb.AuthUserChangePasswordRequest{}
	err := f.GenerateStruct(r)
	if err != nil {
		return err
	}
	_, _ = as.UserChangePassword(r)
	return nil
}

func authenticate(f *fuzz.ConsumeFuzzer, as *authStore) error {
	username, err := f.GetString()
	if err != nil {
		return err
	}
	password, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = as.Authenticate(context.Background(), username, password)
	return nil
}

func userGrantRole(f *fuzz.ConsumeFuzzer, as *authStore) error {
	r := &pb.AuthUserGrantRoleRequest{}
	err := f.GenerateStruct(r)
	if err != nil {
		return err
	}
	_, _ = as.UserGrantRole(r)
	return nil
}

func hasRole(f *fuzz.ConsumeFuzzer, as *authStore) error {
	user, err := f.GetString()
	if err != nil {
		return err
	}
	role, err := f.GetString()
	if err != nil {
		return err
	}
	_ = as.HasRole(user, role)
	return nil
}

func roleGrantPermission(f *fuzz.ConsumeFuzzer, as *authStore) error {
	r := &pb.AuthRoleGrantPermissionRequest{}
	err := f.GenerateStruct(r)
	if err != nil {
		return err
	}
	_, _ = as.RoleGrantPermission(r)
	return nil
}

func userGet(f *fuzz.ConsumeFuzzer, as *authStore) error {
	user, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = as.UserGet(&pb.AuthUserGetRequest{Name: user})
	return nil
}

func FuzzAuthStore(data []byte) int {
	f := fuzz.NewConsumer(data)

	userRoleList, err := createUserRoleList(f)
	if err != nil {
		return 0
	}

	userList, err := createUserList(f)
	if err != nil {
		return 0
	}

	t := &testing.T{}
	as, tearDown := setupAuthStore(t)
	defer tearDown(t)

	// create user roles
	for _, r := range userRoleList {
		_, err = as.RoleAdd(r)
		if err != nil {
			return 0
		}
	}

	// create users
	for _, u := range userList {
		_, err = as.UserAdd(u)
		if err != nil {
			return 0
		}
	}

	for i := 0; i < 20; i++ {
		var err error
		opType, err := f.GetInt()
		switch opTypes[opType%len(opTypes)] {
		case "CheckPassword":
			err = checkPassword(f, as)
		case "UserDelete":
			err = deleteUser(f, as)
		case "Authenticate":
			err = authenticate(f, as)
		case "UserChangePassword":
			err = userChangePassword(f, as)
		case "UserGrantRole":
			err = userGrantRole(f, as)
		case "HasRole":
			err = hasRole(f, as)
		case "RoleGrantPermission":
			err = roleGrantPermission(f, as)
		case "UserGet":
			err = userGet(f, as)
		case "UserList":
			_, _ = as.UserList(&pb.AuthUserListRequest{})
		case "RoleGet":
			err = roleGet(f, as)
		case "RoleRevokePermission":
			err = roleRevokePermission(f, as)
		case "RoleDelete":
			err = roleDelete(f, as)
		case "IsAdminPermitted":
			err = isAdminPermitted(f, as)
		}

		if err != nil {
			return 0
		}
	}
	return 1
}
