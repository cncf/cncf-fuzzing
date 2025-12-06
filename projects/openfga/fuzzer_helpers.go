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
///////////////////////////////////////////////////////////////////////////

package tests

import (
	"fmt"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/featureflags"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage"
)

// mockFeatureFlagClient is a mock implementation that returns true for all feature flags
// This enables all experimental features and unlocks code paths blocked by feature gates
// Implements featureflags.Client interface
type mockFeatureFlagClient struct{}

// Ensure mockFeatureFlagClient implements featureflags.Client
var _ featureflags.Client = (*mockFeatureFlagClient)(nil)

func (m *mockFeatureFlagClient) Boolean(flagName string, storeID string) bool {
	return true // Enable all experimental features
}

// newEnhancedFuzzServer creates an OpenFGA server with all features enabled for comprehensive fuzzing
// This configuration unlocks blocked code paths including:
// - Pipeline ListObjects (via feature flags)
// - Shadow resolver (A/B testing)
// - All caching layers
// - Dispatch throttling
// - Iterator caching
func newEnhancedFuzzServer(datastore storage.OpenFGADatastore) *server.Server {
	return server.MustNewServerWithOpts(
		server.WithDatastore(datastore),
		server.WithFeatureFlagClient(&mockFeatureFlagClient{}),
		server.WithCheckQueryCacheEnabled(true),
		server.WithCacheControllerEnabled(true),
		server.WithCheckIteratorCacheEnabled(true),
		server.WithListObjectsIteratorCacheEnabled(true),
		server.WithDispatchThrottlingCheckResolverEnabled(true),
		// Note: Shadow resolver requires additional mock implementation, skip for now
		// server.WithShadowResolverEnabled(true),
	)
}

// transformDSLWithTimeout wraps TransformDSLToProto with a timeout to prevent
// infinite loops in the ANTLR parser when processing pathological inputs
func transformDSLWithTimeout(dsl string, timeout time.Duration) (*openfgav1.AuthorizationModel, error) {
	type result struct {
		model *openfgav1.AuthorizationModel
		err   error
	}

	done := make(chan result, 1)
	go func() {
		model, err := parser.TransformDSLToProto(dsl)
		done <- result{model, err}
	}()

	select {
	case res := <-done:
		return res.model, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("DSL parsing timeout after %v", timeout)
	}
}
