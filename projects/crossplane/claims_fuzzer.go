package claim

import (
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/resource/fake"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func FuzzPropagateConnection(data []byte) int {
	f := fuzz.NewConsumer(data)
	cp := &fake.Composite{}
	cm := &fake.CompositeClaim{}
	err := f.GenerateStruct(cp)
	if err != nil {
		return 0
	}

	err = f.GenerateStruct(cm)
	if err != nil {
		return 0
	}

	mgcsdata := make(map[string][]byte)
	err = f.FuzzMap(&mgcsdata)
	if err != nil {
		return 0
	}

	c := resource.ClientApplicator{
		Client: &test.MockClient{
			MockGet: test.NewMockGetFn(nil, func(o client.Object) error {
				// The managed secret has some data when we get it.
				s := resource.ConnectionSecretFor(cp, schema.GroupVersionKind{})
				s.Data = mgcsdata

				*o.(*corev1.Secret) = *s
				return nil
			}),
		},
		Applicator: resource.ApplyFn(func(_ context.Context, o client.Object, _ ...resource.ApplyOption) error {
			return nil
		}),
	}
	api := &APIConnectionPropagator{client: c}
	_ = api
	_, _ = api.PropagateConnection(context.Background(), cm, cp)
	return 1
}
