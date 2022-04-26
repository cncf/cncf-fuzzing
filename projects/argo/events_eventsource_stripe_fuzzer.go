package stripe

import (
	"bytes"
	"fmt"
	"net/http"
	"io"
	"github.com/argoproj/argo-events/eventsources/common/webhook"
	"github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
)


var (
	router = &Router{
		route:             webhook.GetFakeRoute(),
		stripeEventSource: &v1alpha1.StripeEventSource{},
	}
)

func FuzzStripeEventsource(data []byte) int {
	router.route.Active = true
	writer := &webhook.FakeHttpWriter{}
	fmt.Println("body: ")
	fmt.Println(string(data))
	fmt.Println("------------------")
	router.HandleRoute(writer, &http.Request{
		Body: io.NopCloser(bytes.NewReader(data)),
	})
	return 1
}
