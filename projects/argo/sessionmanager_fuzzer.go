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

package session

import (
	"context"
	"testing"

	"github.com/argoproj/argo-cd/v2/test"
	"github.com/argoproj/argo-cd/v2/util/settings"
)

var (
	mgr *SessionManager
)

func init() {
	testing.Init()
	redisClient, _ := test.NewInMemoryRedis()

	settingsMgr := settings.NewSettingsManager(context.Background(), getKubeClient("pass", true), "argocd")
	mgr = newSessionManager(settingsMgr, getProjLister(), NewUserStateStorage(redisClient))
}

func FuzzSessionmanagerParse(data []byte) int {
	_, _, _ = mgr.VerifyToken(string(data))
	return 1
}

func FuzzVerifyUsernamePassword(data []byte) int {
	if !(len(data)%2 == 0) || len(data) < 10 {
		return 0
	}
	username := string(data[0 : len(data)/2])
	password := string(data[(len(data)/2)+1:])
	_ = mgr.VerifyUsernamePassword(username, password)
	return 1
}
