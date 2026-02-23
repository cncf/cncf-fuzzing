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
	"strconv"
	"strings"
	"testing"

	"github.com/argoproj/argo-cd/v3/test"
	"github.com/argoproj/argo-cd/v3/util/settings"
	"golang.org/x/crypto/bcrypt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var (
	mgr *SessionManager
)

func getKubeClientForFuzz(pass string, enabled bool) *fake.Clientset {
	bcryptBytes, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	capabilitiesStr := []string{string(settings.AccountCapabilityLogin), string(settings.AccountCapabilityApiKey)}

	return fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-cm",
			Namespace: "argocd",
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "argocd",
			},
		},
		Data: map[string]string{
			"admin":         strings.Join(capabilitiesStr, ","),
			"admin.enabled": strconv.FormatBool(enabled),
		},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-secret",
			Namespace: "argocd",
		},
		Data: map[string][]byte{
			"admin.password":   bcryptBytes,
			"server.secretkey": []byte("Hello, world!"),
		},
	})
}

func init() {
	testing.Init()
	redisClient, _ := test.NewInMemoryRedis()

	settingsMgr := settings.NewSettingsManager(context.Background(), getKubeClientForFuzz("pass", true), "argocd")
	mgr = newSessionManager(settingsMgr, getProjLister(), NewUserStateStorage(redisClient))
}

func FuzzSessionmanagerParse(data []byte) int {
	_, _, _ = mgr.VerifyToken(context.Background(), string(data))
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
