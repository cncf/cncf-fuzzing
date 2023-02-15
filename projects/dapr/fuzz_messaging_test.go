// Copyright 2023 the cncf-fuzzing authors
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

package messaging

import (
	"bytes"
	"context"
	"testing"
	stdTesting "testing"

	"github.com/phayes/freeport"
	"google.golang.org/grpc"

	invokev1 "github.com/dapr/dapr/pkg/messaging/v1"
	commonv1pb "github.com/dapr/dapr/pkg/proto/common/v1"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	messaging *directMessaging
)

func prepareEnvironment(t *stdTesting.T, enableStreaming bool, chunks []string) (*directMessaging, func()) {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	server := startInternalServer(port, enableStreaming, chunks)
	clientConn := createTestClient(port)

	messaging := NewDirectMessaging(NewDirectMessagingOpts{
		MaxRequestBodySize: 10 << 20,
		ClientConnFn: func(ctx context.Context, address string, id string, namespace string, customOpts ...grpc.DialOption) (*grpc.ClientConn, func(destroy bool), error) {
			return clientConn, func(_ bool) {}, nil
		},
		IsStreamingEnabled: true,
	}).(*directMessaging)

	teardown := func() {
		server.Stop()
		clientConn.Close()
	}

	return messaging, teardown
}

func init() {
	messaging, _ = prepareEnvironment(&stdTesting.T{}, true, nil)
}

func FuzzInvokeRemote(f *testing.F) {
	f.Fuzz(func(t *testing.T, data1, data2, data3 []byte, actorType, actorID string) {
		ff := fuzz.NewConsumer(data1)
		ff.AllowUnexportedFields()
		ir := &commonv1pb.InvokeRequest{}
		ff.GenerateStruct(ir)
		md := make(map[string][]string)
		ff.FuzzMap(&md)
		r := invokev1.FromInvokeRequestMessage(ir).
			WithRawData(bytes.NewReader(data2)).
			WithRawDataBytes(data3).
			WithActor(actorType, actorID).
			WithMetadata(md)
		_, _, _ = messaging.invokeRemote(context.Background(), "app1", "namespace1", "addr1", r)
	})
}
