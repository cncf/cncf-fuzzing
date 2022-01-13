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

package project

import (
	"context"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/golang-jwt/jwt/v4"

	"github.com/argoproj/pkg/sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8scache "k8s.io/client-go/tools/cache"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient/project"
	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	apps "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned/fake"
	informer "github.com/argoproj/argo-cd/v2/pkg/client/informers/externalversions"
	"github.com/argoproj/argo-cd/v2/server/rbacpolicy"
	"github.com/argoproj/argo-cd/v2/test"
	"github.com/argoproj/argo-cd/v2/util/db"
	"github.com/argoproj/argo-cd/v2/util/session"
	"github.com/argoproj/argo-cd/v2/util/settings"
)

var (
	tokenName = "testToken"
	//testNamespace = "default"
)

func FuzzValidateProject(data []byte) int {
	f := fuzz.NewConsumer(data)
	proj := &v1alpha1.AppProject{}
	err := f.GenerateStruct(proj)
	if err != nil {
		return 0
	}
	_ = proj.ValidateProject()
	return 1
}

func FuzzParseUnverified(data []byte) int {
	f := fuzz.NewConsumer(data)
	parser := &jwt.Parser{}
	err := f.GenerateStruct(parser)
	if err != nil {
		return 0
	}
	tokenString, err := f.GetString()
	if err != nil {
		return 0
	}
	claims := jwt.StandardClaims{}
	_, _, _ = parser.ParseUnverified(tokenString, &claims)
	return 1
}

func FuzzCreateToken(data []byte) int {

	f := fuzz.NewConsumer(data)
	r := &project.ProjectTokenCreateRequest{}
	err := f.GenerateStruct(r)
	if err != nil {
		return 0
	}

	kubeclientset := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "argocd-cm",
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "argocd",
			},
		},
	}, &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "argocd-secret",
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			"admin.password":   []byte("test"),
			"server.secretkey": []byte("test"),
		},
	})
	existingProj := v1alpha1.AppProject{
		ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: testNamespace},
		Spec: v1alpha1.AppProjectSpec{
			Destinations: []v1alpha1.ApplicationDestination{
				{Namespace: "ns1", Server: "https://server1"},
				{Namespace: "ns2", Server: "https://server2"},
			},
			SourceRepos: []string{"https://github.com/argoproj/argo-cd.git"},
		},
	}

	settingsMgr := settings.NewSettingsManager(context.Background(), kubeclientset, testNamespace)

	sessionMgr := session.NewSessionManager(settingsMgr, test.NewFakeProjLister(), "", session.NewUserStateStorage(nil))
	projectWithRole := existingProj.DeepCopy()

	projectWithRole.Spec.Roles = []v1alpha1.ProjectRole{{Name: tokenName}}
	r.Project = projectWithRole.Name
	r.Role = tokenName
	r.ExpiresIn = 1

	argoDB := db.NewDB("default", settingsMgr, kubeclientset)

	enforcer := newEnforcer(kubeclientset)
	_ = enforcer.SetBuiltinPolicy(`p, *, *, *, *, deny`)
	enforcer.SetClaimsEnforcerFunc(nil)

	ctx := context.Background()
	fakeAppsClientset := apps.NewSimpleClientset()
	factory := informer.NewSharedInformerFactoryWithOptions(fakeAppsClientset, 0, informer.WithNamespace(""), informer.WithTweakListOptions(func(options *metav1.ListOptions) {}))
	projInformer := factory.Argoproj().V1alpha1().AppProjects().Informer()
	go projInformer.Run(ctx.Done())
	if !k8scache.WaitForCacheSync(ctx.Done(), projInformer.HasSynced) {
		panic("Timed out waiting for caches to sync")
	}

	// nolint:staticcheck
	ctx = context.WithValue(context.Background(), "claims", &jwt.MapClaims{"groups": []string{"my-group"}})
	policyEnf := rbacpolicy.NewRBACPolicyEnforcer(enforcer, nil)
	policyEnf.SetScopes([]string{"groups"})

	projectServer := NewServer("default", fake.NewSimpleClientset(), apps.NewSimpleClientset(projectWithRole), enforcer, sync.NewKeyLock(), sessionMgr, policyEnf, projInformer, settingsMgr, argoDB)

	_, _ = projectServer.CreateToken(ctx, r)
	return 1
}
