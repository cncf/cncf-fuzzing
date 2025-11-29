// Copyright 2025 the cncf-fuzzing authors
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

package fuzz

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install"
	"kubevirt.io/kubevirt/pkg/virt-operator/util"
)

var (
	namespace = "fake-namespace"

	getConfig = func(registry, version string) *util.KubeVirtDeploymentConfig {
		return util.GetTargetConfigFromKV(&v1.KubeVirt{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
			},
			Spec: v1.KubeVirtSpec{
				ImageRegistry: registry,
				ImageTag:      version,
			},
		})
	}

	config = getConfig("fake-registry", "v9.9.9")
)

func FuzzLoadInstallStrategyFromCache(f *testing.F) {
	// Seed with valid YAML manifests
	f.Add("apiVersion: v1\nkind: Service\nmetadata:\n  name: virt-api", false)
	f.Add("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: virt-controller\nspec:\n  replicas: 2", false)
	
	// Seed with invalid/malformed manifests
	f.Add("invalid yaml: [[[", false)
	f.Add("apiVersion: v1\nkind: InvalidKind", false)
	f.Add("", false)
	
	// Seed with encoded manifests (gzip+base64)
	f.Add("H4sIAAAAAAAA/0rOyEzLSS0u0csqLU4tUiguKSpN1UvOz9VLzs8FAAAAAf//AQAA//9qLY1zJAAAAA==", true)
	f.Add("invalid base64 !!!", true)
	
	// Seed with large manifests
	f.Add(string(make([]byte, 10000)), false)
	
	// Seed with special characters
	f.Add("apiVersion: v1\nkind: ConfigMap\ndata:\n  key: \"../../etc/passwd\"", false)
	f.Add("apiVersion: v1\nkind: Secret\nstringData:\n  password: \"\x00\x01\x02\"", false)

	f.Fuzz(func(t *testing.T, data string, encoded bool) {
		stores := util.Stores{}
		stores.InstallStrategyConfigMapCache = cache.NewStore(cache.MetaNamespaceKeyFunc)

		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "plaintext-install-strategy",
				Namespace:    config.GetNamespace(),
				Annotations: map[string]string{
					v1.InstallStrategyVersionAnnotation:    config.GetKubeVirtVersion(),
					v1.InstallStrategyRegistryAnnotation:   config.GetImageRegistry(),
					v1.InstallStrategyIdentifierAnnotation: config.GetDeploymentID(),
				},
			},
			Data: map[string]string{
				"manifests": data,
			},
		}
		if encoded {
			configMap.Annotations[v1.InstallStrategyConfigMapEncoding] = install.ManifestsEncodingGzipBase64
		}
		stores.InstallStrategyConfigMapCache.Add(configMap)
		_, _ = install.LoadInstallStrategyFromCache(stores, config)
	})
}
