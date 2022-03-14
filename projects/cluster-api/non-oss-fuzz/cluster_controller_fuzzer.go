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

package cluster

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	// +kubebuilder:scaffold:imports
	. "github.com/onsi/gomega"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/api/v1beta1/index"
	"sigs.k8s.io/cluster-api/controllers/remote"
	machinecontroller "sigs.k8s.io/cluster-api/internal/controllers/machine"
	"sigs.k8s.io/cluster-api/internal/test/envtest"
)

const (
	timeout                       = time.Second * 30
	clusterReconcileNamespaceFuzz = "test-cluster-reconcile"
)

var (
	env         *envtest.Environment
	ctx         = ctrl.SetupSignalHandler()
	fakeScheme  = runtime.NewScheme()
	fuzzInitter sync.Once
)

// Checks whether the directory of a filename exists.
// If it doesn't exists, then it is created.
func createFile(fileNamePath, fileContents string) error {
	path := filepath.Dir(fileNamePath)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fileNamePath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fileContents)
	if err != nil {
		return err
	}
	return nil
}

func createCrdFiles() {
	crds := envtest.CrdMap

	for k, v := range crds {
		err := createFile(k, v)
		if err != nil {
			panic(err)
		}
	}
}

func fuzzInit() {
	createCrdFiles()
	_ = clientgoscheme.AddToScheme(fakeScheme)
	_ = clusterv1.AddToScheme(fakeScheme)
	_ = apiextensionsv1.AddToScheme(fakeScheme)
	TestMain()
}

func TestMain() {
	m := &testing.M{}
	setupIndexes := func(ctx context.Context, mgr ctrl.Manager) {
		if err := index.AddDefaultIndexes(ctx, mgr); err != nil {
			panic(fmt.Sprintf("unable to setup index: %v", err))
		}
	}

	setupReconcilers := func(ctx context.Context, mgr ctrl.Manager) {
		// Set up a ClusterCacheTracker and ClusterCacheReconciler to provide to controllers
		// requiring a connection to a remote cluster
		log := ctrl.Log.WithName("remote").WithName("ClusterCacheTracker")
		tracker, err := remote.NewClusterCacheTracker(
			mgr,
			remote.ClusterCacheTrackerOptions{
				Log:     &log,
				Indexes: remote.DefaultIndexes,
			},
		)
		if err != nil {
			panic(fmt.Sprintf("unable to create cluster cache tracker: %v", err))
		}
		if err := (&remote.ClusterCacheReconciler{
			Client:  mgr.GetClient(),
			Log:     ctrl.Log.WithName("remote").WithName("ClusterCacheReconciler"),
			Tracker: tracker,
		}).SetupWithManager(ctx, mgr, controller.Options{MaxConcurrentReconciles: 1}); err != nil {
			panic(fmt.Sprintf("Failed to start ClusterCacheReconciler: %v", err))
		}
		if err := (&Reconciler{
			Client:    mgr.GetClient(),
			APIReader: mgr.GetClient(),
		}).SetupWithManager(ctx, mgr, controller.Options{MaxConcurrentReconciles: 1}); err != nil {
			panic(fmt.Sprintf("Failed to start ClusterReconciler: %v", err))
		}
		if err := (&machinecontroller.Reconciler{
			Client:    mgr.GetClient(),
			APIReader: mgr.GetAPIReader(),
			Tracker:   tracker,
		}).SetupWithManager(ctx, mgr, controller.Options{MaxConcurrentReconciles: 1}); err != nil {
			panic(fmt.Sprintf("Failed to start MachineReconciler: %v", err))
		}
	}

	SetDefaultEventuallyPollingInterval(100 * time.Millisecond)
	SetDefaultEventuallyTimeout(timeout)

	envtest.Run(ctx, envtest.RunInput{
		M:                m,
		SetupEnv:         func(e *envtest.Environment) { env = e },
		SetupIndexes:     setupIndexes,
		SetupReconcilers: setupReconcilers,
	})
}

// This fuzzer does not run on OSS-fuzz because the kubebuilder
// binaries are not available in the OSS-fuzz runtime environement.
func FuzzClusterController(data []byte) int {
	fuzzInitter.Do(fuzzInit)
	f := fuzz.NewConsumer(data)
	instance := &clusterv1.Cluster{}
	err := f.GenerateStruct(instance)
	if err != nil {
		return 0
	}

	ns, err := env.CreateNamespace(ctx, clusterReconcileNamespaceFuzz)
	if err != nil {
		return 0
	}
	defer func() {
		if err := env.Delete(ctx, ns); err != nil {
			panic(err)
		}
	}()

	err = env.Create(ctx, instance)
	if err != nil {
		return 0
	}
	defer func() {
		err := env.Delete(ctx, instance)
		if err != nil {
			panic(err)
		}
	}()
	return 1
}
