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

package http

import (
	"context"
	"errors"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	contribPubsub "github.com/dapr/components-contrib/pubsub"
	state "github.com/dapr/components-contrib/state/in-memory"
	"github.com/dapr/kit/logger"
	"github.com/valyala/fasthttp"

	"github.com/dapr/dapr/pkg/actors"
	"github.com/dapr/dapr/pkg/actors/reminders"
	"github.com/dapr/dapr/pkg/channel"
	"github.com/dapr/dapr/pkg/grpc/universalapi"
	invokev1 "github.com/dapr/dapr/pkg/messaging/v1"
	commonv1pb "github.com/dapr/dapr/pkg/proto/common/v1"
	runtimev1pb "github.com/dapr/dapr/pkg/proto/runtime/v1"
	"github.com/dapr/dapr/pkg/resiliency"
	"github.com/dapr/dapr/pkg/runtime/compstore"
)

var (
	contentTypes = map[int]string{
		0:  "application/java-archive",
		1:  "application/EDI-X12",
		2:  "application/EDIFACT",
		3:  "application/javascript",
		4:  "application/octet-stream",
		5:  "application/ogg",
		6:  "application/pdf",
		7:  "application/xhtml+xml",
		8:  "application/x-shockwave-flash",
		9:  "application/json",
		10: "application/ld+json",
		11: "application/xml",
		12: "application/zip",
		13: "application/x-www-form-urlencoded",
		14: "audio/mpeg",
		15: "audio/x-ms-wma",
		16: "audio/vnd.rn-realaudio",
		17: "audio/x-wav",
		18: "image/gif",
		19: "image/jpeg",
		20: "image/png",
		21: "image/tiff",
		22: "image/vnd.microsoft.icon",
		23: "image/x-icon",
		24: "image/vnd.djvu",
		25: "image/svg+xml",
		26: "multipart/mixed",
		27: "multipart/alternative",
		28: "multipart/related",
		29: "multipart/form-data",
		30: "text/css",
		31: "text/csv",
		32: "text/html",
		33: "text/javascript",
		34: "text/plain",
		35: "text/xml",
		36: "video/mpeg",
		37: "video/mp4",
		38: "video/quicktime",
		39: "video/x-ms-wmv",
		40: "video/x-msvideo",
		41: "video/x-flv",
		42: "video/webm",
		43: "application/vnd.android.package-archive",
		44: "application/vnd.oasis.opendocument.text",
		45: "application/vnd.oasis.opendocument.spreadsheet",
		46: "application/vnd.oasis.opendocument.presentation",
		47: "application/vnd.oasis.opendocument.graphics",
		48: "application/vnd.ms-excel",
		49: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		50: "application/vnd.ms-powerpoint",
		51: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		52: "application/msword",
		53: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		54: "application/vnd.mozilla.xul+xml",
	}
)

func FuzzOnPostStateTransaction(f *testing.F) {
	f.Fuzz(func(t *testing.T, body []byte, userValue string) {
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("storeName", userValue)

		cs := compstore.New()
		ss := state.NewInMemoryStateStore(logger.NewLogger("fuzz"))
		cs.AddStateStore("inmemory", ss)
		a := &api{
			universal: &universalapi.UniversalAPI{
				CompStore: cs,
			},
		}
		a.onPostStateTransaction(reqCtx)
	})
}

type FuzzPublisher struct {
	data []byte
}

type FuzzPubSub struct{}

func (a *FuzzPubSub) Close() error {
	return nil
}

func (a *FuzzPubSub) Features() []contribPubsub.Feature {
	return []contribPubsub.Feature{contribPubsub.FeatureSubscribeWildcards}
}

func (a *FuzzPubSub) Init(_ context.Context, metadata contribPubsub.Metadata) error {
	return nil
}

func (a *FuzzPubSub) Publish(_ context.Context, req *contribPubsub.PublishRequest) error {
	return nil
}

func (a *FuzzPubSub) Subscribe(ctx context.Context, req contribPubsub.SubscribeRequest, handler contribPubsub.Handler) error {
	return nil
}

// GetComponentMetadata returns the metadata of the component.
func (a *FuzzPubSub) GetComponentMetadata() map[string]string {
	return map[string]string{}
}

func (fp *FuzzPublisher) BulkPublish(req *contribPubsub.BulkPublishRequest) (contribPubsub.BulkPublishResponse, error) {
	ff := fuzz.NewConsumer(fp.data)
	resp := &contribPubsub.BulkPublishResponse{}
	ff.GenerateStruct(resp)
	return *resp, nil
}

func (fp *FuzzPublisher) GetPubSub(pubsubName string) contribPubsub.PubSub { return &FuzzPubSub{} }
func (fp *FuzzPublisher) Publish(req *contribPubsub.PublishRequest) error  { return nil }

func FuzzOnBulkPublish(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2 string) {
		a := &api{
			pubsubAdapter: &FuzzPublisher{
				data: data,
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("pubsubname", userValue1)
		reqCtx.SetUserValue("topic", userValue2)
		a.onBulkPublish(reqCtx)
	})
}

func FuzzOnPublish(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, appID string) {
		a := &api{
			pubsubAdapter: &FuzzPublisher{
				data: data,
			},
			universal: &universalapi.UniversalAPI{
				AppID: appID,
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("pubsubname", userValue1)
		reqCtx.SetUserValue("topic", userValue2)
		a.onPublish(reqCtx)
	})
}

type FuzzActors struct {
	ff *fuzz.ConsumeFuzzer
}

func (a *FuzzActors) Call(ctx context.Context, req *invokev1.InvokeMethodRequest) (*invokev1.InvokeMethodResponse, error) {
	a.ff.AllowUnexportedFields()
	pb := &commonv1pb.InvokeResponse{}
	a.ff.GenerateStruct(pb)
	contType, err := a.ff.GetInt()
	if err != nil {
		return nil, errors.New("empty resp")
	}
	pb.ContentType = contentTypes[contType%len(contentTypes)]
	resp := invokev1.NewInvokeMethodResponse(int32(0), "", nil).WithMessage(pb)
	if !resp.HasMessageData() {
		return nil, errors.New("empty resp")
	}
	return resp, nil
}

func (a *FuzzActors) Init() error { return nil }

func (a *FuzzActors) Stop() {}

func (a *FuzzActors) GetState(ctx context.Context, req *actors.GetStateRequest) (*actors.StateResponse, error) {
	return nil, nil
}

func (a *FuzzActors) TransactionalStateOperation(ctx context.Context, req *actors.TransactionalRequest) error {
	return nil
}

func (a *FuzzActors) GetReminder(ctx context.Context, req *actors.GetReminderRequest) (*reminders.Reminder, error) {
	rem := &reminders.Reminder{}
	a.ff.GenerateStruct(rem)
	return rem, nil
}

func (a *FuzzActors) CreateReminder(ctx context.Context, req *actors.CreateReminderRequest) error {
	return nil
}

func (a *FuzzActors) DeleteReminder(ctx context.Context, req *actors.DeleteReminderRequest) error {
	return nil
}

func (a *FuzzActors) RenameReminder(ctx context.Context, req *actors.RenameReminderRequest) error {
	return nil
}

func (a *FuzzActors) CreateTimer(ctx context.Context, req *actors.CreateTimerRequest) error {
	return nil
}

func (a *FuzzActors) DeleteTimer(ctx context.Context, req *actors.DeleteTimerRequest) error {
	return nil
}

func (a *FuzzActors) IsActorHosted(ctx context.Context, req *actors.ActorHostedRequest) bool {
	return true
}

func (a *FuzzActors) GetActiveActorsCount(ctx context.Context) []*runtimev1pb.ActiveActorsCount {
	aac := make([]*runtimev1pb.ActiveActorsCount, 0)
	return aac
}

func (a *FuzzActors) RegisterInternalActor(ctx context.Context, actorType string, actor actors.InternalActor) error {
	return nil
}

type FuzzResiliency struct {
	data []byte
}

func (r *FuzzResiliency) EndpointPolicy(service, endpoint string) *resiliency.PolicyDefinition {
	pd := &resiliency.PolicyDefinition{}
	ff := fuzz.NewConsumer(r.data)
	ff.GenerateStruct(pd)
	return pd
}

func (r *FuzzResiliency) ActorPreLockPolicy(actorType string, id string) *resiliency.PolicyDefinition {
	pd := &resiliency.PolicyDefinition{}
	ff := fuzz.NewConsumer(r.data)
	ff.GenerateStruct(pd)
	return pd
}

func (r *FuzzResiliency) ActorPostLockPolicy(actorType string, id string) *resiliency.PolicyDefinition {
	return nil
}
func (r *FuzzResiliency) ComponentOutboundPolicy(name string, componentType resiliency.ComponentType) *resiliency.PolicyDefinition {
	return nil
}
func (r *FuzzResiliency) ComponentInboundPolicy(name string, componentType resiliency.ComponentType) *resiliency.PolicyDefinition {
	return nil
}
func (r *FuzzResiliency) BuiltInPolicy(name resiliency.BuiltInPolicyName) *resiliency.PolicyDefinition {
	return nil
}
func (r *FuzzResiliency) PolicyDefined(target string, policyType resiliency.PolicyType) (exists bool) {
	return true
}

func FuzzOnDirectActorMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data, data2 []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
			resiliency: &FuzzResiliency{
				data: data2,
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		reqCtx.SetUserValue("method", "POST")
		a.onDirectActorMessage(reqCtx)
	})
}

func FuzzOnDeleteActorTimer(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onDeleteActorTimer(reqCtx)
	})
}

func FuzzOnGetActorReminder(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onGetActorReminder(reqCtx)
	})
}

func FuzzOnActorStateTransaction(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onActorStateTransaction(reqCtx)
	})
}

func FuzzOnDeleteActorReminder(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onDeleteActorReminder(reqCtx)
	})
}

func FuzzOnCreateActorTimer(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onCreateActorTimer(reqCtx)
	})
}

func FuzzOnRenameActorReminder(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onRenameActorReminder(reqCtx)
	})
}

func FuzzOnCreateActorReminder(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data []byte, userValue1, userValue2, userValue3 string) {
		ff := fuzz.NewConsumer(data)
		a := &api{
			universal: &universalapi.UniversalAPI{
				Actors: &FuzzActors{
					ff: ff,
				},
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("actorType", userValue1)
		reqCtx.SetUserValue("actorId", userValue2)
		reqCtx.SetUserValue("name", userValue3)
		a.onCreateActorReminder(reqCtx)
	})
}

type FuzzDirectMessaging struct {
	ff *fuzz.ConsumeFuzzer
}

func (dm *FuzzDirectMessaging) Invoke(ctx context.Context, targetAppID string, req *invokev1.InvokeMethodRequest) (*invokev1.InvokeMethodResponse, error) {
	dm.ff.AllowUnexportedFields()
	pb := &commonv1pb.InvokeResponse{}
	dm.ff.GenerateStruct(pb)
	contType, err := dm.ff.GetInt()
	if err != nil {
		return nil, errors.New("empty resp")
	}
	pb.ContentType = contentTypes[contType%len(contentTypes)]
	resp := invokev1.NewInvokeMethodResponse(int32(0), "", nil).WithMessage(pb)
	if !resp.HasMessageData() {
		return nil, errors.New("empty resp")
	}
	return resp, nil
}

func (dm *FuzzDirectMessaging) SetAppChannel(appChannel channel.AppChannel) {}
func (dm *FuzzDirectMessaging) SetHTTPEndpointsAppChannel(appChannel channel.HTTPEndpointAppChannel) {
}

func FuzzOnDirectMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, data, data2 []byte, userValue string) {
		ff := fuzz.NewConsumer(data)
		fdm := &FuzzDirectMessaging{ff: ff}

		cs := compstore.New()
		ss := state.NewInMemoryStateStore(logger.NewLogger("fuzz"))
		cs.AddStateStore("inmemory", ss)

		a := &api{
			directMessaging: fdm,
			resiliency: &FuzzResiliency{
				data: data2,
			},
			universal: &universalapi.UniversalAPI{
				CompStore: cs,
			},
		}
		reqCtx := &fasthttp.RequestCtx{}
		req := &fasthttp.Request{}
		req.SetBody(body)
		reqCtx.SetUserValue("id", userValue)
		reqCtx.SetUserValue("method", "POST")
		a.onDirectMessage(reqCtx)
	})
}
