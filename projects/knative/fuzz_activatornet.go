package net

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	pkgnet "knative.dev/networking/pkg/apis/networking"
	"knative.dev/serving/pkg/queue"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"knative.dev/pkg/injection"

	"knative.dev/pkg/controller"
)

func NewFuzzLogger() *zap.SugaredLogger {
	var config zap.Config
	config = zap.NewProductionConfig()
	// Config customization goes here if any
	config.OutputPaths = []string{os.DevNull}
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	return logger.Named("knative-log").Sugar()
}

func FuzzNewRevisionThrottler(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("fatal error: out of memory")
				debug.PrintStack()
				panic("fatal error: out of memory")

			}
		}()
		ff := fuzz.NewConsumer(data)

		ip1, err := ff.GetString()
		if err != nil {
			return
		}

		ip2, err := ff.GetString()
		if err != nil {
			return
		}

		ip3, err := ff.GetString()
		if err != nil {
			return
		}

		revName := types.NamespacedName{}
		ff.GenerateStruct(&revName)

		containerConcurrency, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		params := queue.BreakerParams{}
		ff.GenerateStruct(&params)
		if params.QueueDepth <= 0 {
			t.Skip()
		}
		if params.MaxConcurrency < 0 {
			t.Skip()
		}
		if params.InitialCapacity < 0 || params.InitialCapacity > params.MaxConcurrency {
			t.Skip()
		}
		logger := NewFuzzLogger()
		rt := newRevisionThrottler(revName, containerConcurrency%10, pkgnet.ServicePortNameHTTP1, params, logger)

		ctx, cancel := SetupFakeContextWithCancel()
		defer cancel()
		throttler := newTestThrottler(ctx)
		throttler.revisionThrottlers[revName] = rt

		update := revisionDestsUpdate{
			Rev:           revName,
			ClusterIPDest: "",
			Dests:         sets.NewString(ip1, ip2, ip3),
		}
		throttler.handleUpdate(update)
	})
}

func SetupFakeContextWithCancel() (context.Context, context.CancelFunc) {
	ctx, c := context.WithCancel(context.Background())
	ctx = controller.WithEventRecorder(ctx, record.NewFakeRecorder(1000))
	ctx, _ = injection.Fake.SetupInformers(ctx, &rest.Config{})
	return ctx, c
}
