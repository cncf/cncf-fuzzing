package metrics

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func FuzzNewObservabilityConfigFromConfigMap(f *testing.F) {
	f.Fuzz(func(t *testing.T, configMapData []byte) {
		ff := fuzz.NewConsumer(configMapData)
		cm := &corev1.ConfigMap{}
		ff.GenerateStruct(cm)
		_, _ = NewObservabilityConfigFromConfigMap(cm)
	})
}
