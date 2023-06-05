package http

import (
	"testing"
	"github.com/dapr/dapr/pkg/config"
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
)

func FuzzIsEndpointAllowed(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		endpoint := Endpoint{}
		ff.GenerateStruct(&endpoint)
		if endpoint.Version == "" {
			return
		}
		if endpoint.Route == "" {
			return
		}
		rule := config.APIAccessRule{}
		ff.GenerateStruct(&rule)
		if rule.Version == "" {
			return
		}
		if rule.Version != endpoint.Version {
			return
		}
		if rule.Name == "" {
			return
		}

		if len(endpoint.Route) < 2 {
			return
		}

		if len(rule.Name) < 2 {
			return
		}

		if endpoint.Route[0] == rule.Name[0] {
			return
		}

		if endpoint.Route[1] == rule.Name[1] {
			return
		}

		if endpointMatchesAPIAccessRule(endpoint, rule) == true {
			panic("Should not be true")
		}
	})
}
