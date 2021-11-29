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

package v2auth

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.etcd.io/etcd/server/v3/etcdserver"
	"go.etcd.io/etcd/server/v3/etcdserver/api/v2store"
	"go.uber.org/zap"
)

var (
	olduser = `{"user": "cat", "roles" : ["animal"]}`
	newuser = `{"user": "cat", "roles" : ["animal", "pet"]}`
	d       = &testDoer{
		get: []etcdserver.Response{
			{
				Event: nil,
			},
			{
				Event: &v2store.Event{
					Action: v2store.Get,
					Node: &v2store.NodeExtern{
						Key:   StorePermsPrefix + "/users/cat",
						Value: &olduser,
					},
				},
			},
			{
				Event: &v2store.Event{
					Action: v2store.Get,
					Node: &v2store.NodeExtern{
						Key:   StorePermsPrefix + "/users/cat",
						Value: &olduser,
					},
				},
			},
		},
		put: []etcdserver.Response{
			{
				Event: &v2store.Event{
					Action: v2store.Update,
					Node: &v2store.NodeExtern{
						Key:   StorePermsPrefix + "/users/cat",
						Value: &olduser,
					},
				},
			},
			{
				Event: &v2store.Event{
					Action: v2store.Update,
					Node: &v2store.NodeExtern{
						Key:   StorePermsPrefix + "/users/cat",
						Value: &newuser,
					},
				},
			},
		},
		explicitlyEnabled: true,
	}
)

func FuzzCreateOrUpdateUser(data []byte) int {
	f := fuzz.NewConsumer(data)
	user := User{}
	err := f.GenerateStruct(&user)
	if err != nil {
		return 0
	}
	s := store{lg: zap.NewExample(), server: d, timeout: testTimeout, ensuredOnce: true, PasswordStore: fastPasswordStore{}}
	_, _, _ = s.CreateOrUpdateUser(user)
	return 1
}
