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

package oxia

import (
	"fmt"
	"testing"

	"github.com/oxia-db/oxia/oxiad/coordinator/metadata"
	"github.com/oxia-db/oxia/oxiad/coordinator/model"
)

// FuzzMetadataLoadStore tests coordinator metadata storage layer (in-memory provider).
// This tests the Store/Get/Version management and optimistic concurrency control
// without requiring network infrastructure.
//
// Key operations tested:
// - Store cluster configuration
// - Get cluster configuration  
// - Version tracking and optimistic concurrency control
// - ClusterStatus serialization/deserialization
func FuzzMetadataLoadStore(f *testing.F) {
	// Seed 1: Empty namespace map
	f.Add([]byte{0, 0, 1})

	// Seed 2: Single namespace
	f.Add([]byte{1, 3, 2})

	// Seed 3: Multiple namespaces
	f.Add([]byte{5, 5, 10})

	// Seed 4: Many shards
	f.Add([]byte{3, 7, 20, 15})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse input bytes into configuration parameters
		if len(data) < 3 {
			return
		}

		namespaceCount := data[0]
		replicationFactor := uint32(data[1])
		shardCount := uint32(data[2])

		// Limit inputs to reasonable ranges
		if namespaceCount > 10 {
			namespaceCount = namespaceCount % 10
		}
		if replicationFactor > 10 || replicationFactor == 0 {
			replicationFactor = 3
		}
		if shardCount > 100 || shardCount == 0 {
			shardCount = 1
		}

		// Test in-memory provider
		provider := metadata.NewMetadataProviderMemory()
		defer provider.Close()

		// Initial state: should not exist
		cs, version, err := provider.Get()
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if version != metadata.NotExists {
			t.Fatalf("Expected NotExists, got %v", version)
		}
		if cs != nil {
			t.Fatal("Expected nil ClusterStatus")
		}

		// Create cluster configuration from fuzz input
		clusterStatus := &model.ClusterStatus{
			Namespaces: make(map[string]model.NamespaceStatus),
		}

		for i := uint8(0); i < namespaceCount; i++ {
			ns := fmt.Sprintf("ns-%d", i)
			shards := make(map[int64]model.ShardMetadata)

			for shard := int64(0); shard < int64(shardCount); shard++ {
				shards[shard] = model.ShardMetadata{
					Status:      model.ShardStatusSteadyState,
					Term:        1,
					Ensemble:    []model.Server{{Public: fmt.Sprintf("server-%d", shard)}},
					Int32HashRange: model.Int32HashRange{
						Min: uint32(shard * 1000),
						Max: uint32((shard + 1) * 1000),
					},
				}
			}

			clusterStatus.Namespaces[ns] = model.NamespaceStatus{
				ReplicationFactor: replicationFactor,
				Shards:            shards,
			}
		}

		// First store should succeed
		v1, err := provider.Store(clusterStatus, metadata.NotExists)
		if err != nil {
			t.Fatalf("First Store failed: %v", err)
		}
		if v1 != metadata.Version("0") {
			t.Fatalf("Expected version 0, got %v", v1)
		}

		// Get should return stored data
		retrieved, v2, err := provider.Get()
		if err != nil {
			t.Fatalf("Get after Store failed: %v", err)
		}
		if v2 != v1 {
			t.Fatalf("Version mismatch: expected %v, got %v", v1, v2)
		}

		// Verify namespace count matches
		if len(retrieved.Namespaces) != int(namespaceCount) {
			t.Fatalf("Namespace count mismatch: expected %d, got %d", namespaceCount, len(retrieved.Namespaces))
		}

		// Verify shard count in first namespace
		if namespaceCount > 0 {
			firstNS := retrieved.Namespaces["ns-0"]
			if len(firstNS.Shards) != int(shardCount) {
				t.Fatalf("Shard count mismatch: expected %d, got %d", shardCount, len(firstNS.Shards))
			}
			if firstNS.ReplicationFactor != replicationFactor {
				t.Fatalf("Replication factor mismatch: expected %d, got %d", replicationFactor, firstNS.ReplicationFactor)
			}
		}

		// Update with correct version should succeed
		clusterStatus.Namespaces["new-ns"] = model.NamespaceStatus{
			ReplicationFactor: replicationFactor,
			Shards:            make(map[int64]model.ShardMetadata),
		}
		v3, err := provider.Store(clusterStatus, v2)
		if err != nil {
			t.Fatalf("Second Store failed: %v", err)
		}
		if v3 != metadata.Version("1") {
			t.Fatalf("Expected version 1, got %v", v3)
		}

		// Store with wrong version should panic (optimistic concurrency control)
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("Expected panic on version mismatch")
				}
			}()
			_, _ = provider.Store(clusterStatus, v1) // Old version
		}()

		// Final get should return updated data
		finalStatus, finalVersion, err := provider.Get()
		if err != nil {
			t.Fatalf("Final Get failed: %v", err)
		}
		if finalVersion != v3 {
			t.Fatalf("Final version mismatch: expected %v, got %v", v3, finalVersion)
		}
		if len(finalStatus.Namespaces) != int(namespaceCount)+1 {
			t.Fatalf("Expected %d namespaces, got %d", namespaceCount+1, len(finalStatus.Namespaces))
		}
		if _, exists := finalStatus.Namespaces["new-ns"]; !exists {
			t.Fatal("new-ns should exist in final status")
		}
	})
}
