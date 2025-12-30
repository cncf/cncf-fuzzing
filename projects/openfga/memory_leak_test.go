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
	"context"
	"runtime"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzListObjectsMemoryLeak tests GHSA-rxpw-85vw-fx87
// CVE: ListObjects may not release memory properly, causing memory leak DoS
//
// Vulnerability pattern:
// 1. Create model with complex authorization chains
// 2. Write many tuples creating large evaluation graphs
// 3. Call ListObjects repeatedly
// 4. Monitor memory usage
// 5. BUG: In vulnerable versions, memory grows unbounded
func FuzzListObjectsMemoryLeak(f *testing.F) {
	f.Fuzz(func(t *testing.T, modelDSL, user1, user2, user3, user4, user5, user6,
		user7, user8, user9, user10, user11, user12, user13, user14, user15,
		user16, user17, user18, user19, user20, user21, user22, user23, user24,
		user25, user26, user27, user28, user29, user30, dir1, dir2, dir3, dir4,
		dir5, dir6, dir7, dir8, dir9, dir10, dir11, dir12, dir13, dir14, dir15,
		dir16, dir17, dir18, dir19, dir20, dir21, dir22, dir23, dir24, dir25,
		dir26, dir27, dir28, dir29, dir30 string, numObjects uint8,
		parent1, parent2, parchan3, parent4, parent5, parent6,
		parent7, parent8, parent9, parent10, parent11, parent12,
		parent13, parent14, parent15, parent16, parent17, parent18,
		parent19, parent20, parent21, parent22, parent23, parent24,
		parent25, parent26, parent27, parent28, parent29, parent30 string) {

		// Parse model from fuzzer input
		dsl, err := transformDSLWithTimeout(modelDSL, 5*time.Second)
		if err != nil {
			return // Invalid DSL or timeout, skip
		}
		users := []string{
			user1, user2, user3, user4, user5, user6,
			user7, user8, user9, user10, user11, user12,
			user13, user14, user15, user16, user17, user18,
			user19, user20, user21, user22, user23, user24,
			user25, user26, user27, user28, user29, user30,
		}

		dirs := []string{
			dir1, dir2, dir3, dir4, dir5, dir6,
			dir7, dir8, dir9, dir10, dir11, dir12,
			dir13, dir14, dir15, dir16, dir17, dir18,
			dir19, dir20, dir21, dir22, dir23, dir24,
			dir25, dir26, dir27, dir28, dir29, dir30,
		}

		parents := []string{
			parent1, parent2, parchan3, parent4, parent5, parent6,
			parent7, parent8, parent9, parent10, parent11, parent12,
			parent13, parent14, parent15, parent16, parent17, parent18,
			parent19, parent20, parent21, parent22, parent23, parent24,
			parent25, parent26, parent27, parent28, parent29, parent30,
		}

		// Limit objects to prevent legitimate memory growth
		if numObjects > 30 {
			numObjects = 30
		}

		ctx := context.Background()
		datastore := memory.New()
		defer datastore.Close()

		srv := newEnhancedFuzzServer(datastore)
		defer srv.Close()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz"})
		if err != nil {
			return
		}

		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return
		}

		// Write tuples to create evaluation complexity
		var tuples []*openfgav1.TupleKey
		for i := uint8(0); i < numObjects; i++ {
			objStr := dirs[int(i)]

			// Direct viewer
			tuples = append(tuples, &openfgav1.TupleKey{
				Object:   objStr,
				Relation: "viewer",
				User:     users[int(i)],
			})

			// Create parent chain (increases complexity)
			if i > 0 {
				parentStr := parents[int(i)]
				tuples = append(tuples, &openfgav1.TupleKey{
					Object:   objStr,
					Relation: "parent",
					User:     parentStr,
				})
			}
		}

		_, err = srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Writes:               &openfgav1.WriteRequestWrites{TupleKeys: tuples},
		})
		if err != nil {
			return
		}

		// Force GC and get baseline memory
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		baselineAlloc := m1.Alloc

		// Call ListObjects repeatedly (vulnerable versions leak memory here)
		// OPTIMIZATION: Vary iteration patterns to test different code paths
		const iterations = 10
		for i := 0; i < iterations; i++ {
			_, err := srv.ListObjects(ctx, &openfgav1.ListObjectsRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				Type:                 "folder",
				Relation:             "viewer",
				User:                 users[i],
			})
			if err != nil {
				return
			}
		}

		// Force GC and check memory again
		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)
		finalAlloc := m2.Alloc

		// Calculate memory growth
		growth := int64(finalAlloc) - int64(baselineAlloc)

		// Expected: minimal growth (fixed version properly releases memory)
		// Vulnerable: significant growth proportional to iterations

		// Allow some growth for legitimate allocations (caches, etc.)
		// But flag excessive growth indicating a leak
		maxAcceptableGrowth := int64(10 * 1024 * 1024) // 10MB threshold

		if growth > maxAcceptableGrowth {
			t.Fatalf("POTENTIAL MEMORY LEAK GHSA-rxpw-85vw-fx87!\n"+
				"ListObjects called %d times\n"+
				"Memory growth: %d bytes (%.2f MB)\n"+
				"Baseline: %d bytes\n"+
				"Final: %d bytes\n"+
				"Growth exceeds threshold of %.2f MB\n"+
				"This may indicate memory is not released properly",
				iterations,
				growth, float64(growth)/(1024*1024),
				baselineAlloc,
				finalAlloc,
				float64(maxAcceptableGrowth)/(1024*1024))
		}

		// Note: This test is probabilistic and may have false positives/negatives
		// Memory behavior varies by runtime, GC timing, and system state
		// The original CVE was fixed in v1.3.4 by properly releasing goroutines/channels
		// This fuzzer helps catch regression of the fix
	})
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
