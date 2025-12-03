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

	"github.com/openfga/openfga/pkg/server"
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
	// Seed 1: Simple document viewer model
	f.Add("model\n  schema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"document:1", "document:2", "document:3", "document:4", "document:5", "document:6",
		"document:7", "document:8", "document:9", "document:10", "document:11", "document:12",
		"document:13", "document:14", "document:15", "document:16", "document:17", "document:18",
		"document:19", "document:20", "document:21", "document:22", "document:23", "document:24",
		"document:25", "document:26", "document:27", "document:28", "document:29", "document:30",
		uint8(10),
		"document:p1", "document:p2", "document:p3", "document:p4", "document:p5", "document:p6",
		"document:p7", "document:p8", "document:p9", "document:p10", "document:p11", "document:p12",
		"document:p13", "document:p14", "document:p15", "document:p16", "document:p17", "document:p18",
		"document:p19", "document:p20", "document:p21", "document:p22", "document:p23", "document:p24",
		"document:p25", "document:p26", "document:p27", "document:p28", "document:p29", "document:p30")

	// Seed 2: Model with parent relationships
	f.Add("model\n  schema 1.1\ntype user\ntype folder\n  relations\n    define parent: [folder]\n    define viewer: [user] or viewer from parent",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"folder:f1", "folder:f2", "folder:f3", "folder:f4", "folder:f5", "folder:f6",
		"folder:f7", "folder:f8", "folder:f9", "folder:f10", "folder:f11", "folder:f12",
		"folder:f13", "folder:f14", "folder:f15", "folder:f16", "folder:f17", "folder:f18",
		"folder:f19", "folder:f20", "folder:f21", "folder:f22", "folder:f23", "folder:f24",
		"folder:f25", "folder:f26", "folder:f27", "folder:f28", "folder:f29", "folder:f30",
		uint8(15),
		"folder:p1", "folder:p2", "folder:p3", "folder:p4", "folder:p5", "folder:p6",
		"folder:p7", "folder:p8", "folder:p9", "folder:p10", "folder:p11", "folder:p12",
		"folder:p13", "folder:p14", "folder:p15", "folder:p16", "folder:p17", "folder:p18",
		"folder:p19", "folder:p20", "folder:p21", "folder:p22", "folder:p23", "folder:p24",
		"folder:p25", "folder:p26", "folder:p27", "folder:p28", "folder:p29", "folder:p30")

	// Seed 3: Model with group membership
	f.Add("model\n  schema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype resource\n  relations\n    define viewer: [user, group#member]",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"resource:r1", "resource:r2", "resource:r3", "resource:r4", "resource:r5", "resource:r6",
		"resource:r7", "resource:r8", "resource:r9", "resource:r10", "resource:r11", "resource:r12",
		"resource:r13", "resource:r14", "resource:r15", "resource:r16", "resource:r17", "resource:r18",
		"resource:r19", "resource:r20", "resource:r21", "resource:r22", "resource:r23", "resource:r24",
		"resource:r25", "resource:r26", "resource:r27", "resource:r28", "resource:r29", "resource:r30",
		uint8(20),
		"group:g1", "group:g2", "group:g3", "group:g4", "group:g5", "group:g6",
		"group:g7", "group:g8", "group:g9", "group:g10", "group:g11", "group:g12",
		"group:g13", "group:g14", "group:g15", "group:g16", "group:g17", "group:g18",
		"group:g19", "group:g20", "group:g21", "group:g22", "group:g23", "group:g24",
		"group:g25", "group:g26", "group:g27", "group:g28", "group:g29", "group:g30")

	// Seed 4: Model with owner and editor relations
	f.Add("model\n  schema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n    define editor: [user] or owner\n    define viewer: [user] or editor",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"document:d1", "document:d2", "document:d3", "document:d4", "document:d5", "document:d6",
		"document:d7", "document:d8", "document:d9", "document:d10", "document:d11", "document:d12",
		"document:d13", "document:d14", "document:d15", "document:d16", "document:d17", "document:d18",
		"document:d19", "document:d20", "document:d21", "document:d22", "document:d23", "document:d24",
		"document:d25", "document:d26", "document:d27", "document:d28", "document:d29", "document:d30",
		uint8(12),
		"user:owner1", "user:owner2", "user:owner3", "user:owner4", "user:owner5", "user:owner6",
		"user:owner7", "user:owner8", "user:owner9", "user:owner10", "user:owner11", "user:owner12",
		"user:owner13", "user:owner14", "user:owner15", "user:owner16", "user:owner17", "user:owner18",
		"user:owner19", "user:owner20", "user:owner21", "user:owner22", "user:owner23", "user:owner24",
		"user:owner25", "user:owner26", "user:owner27", "user:owner28", "user:owner29", "user:owner30")

	// Seed 5: Organization hierarchy model
	f.Add("model\n  schema 1.1\ntype user\ntype org\n  relations\n    define member: [user]\ntype team\n  relations\n    define org: [org]\n    define member: [user] or member from org",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"team:t1", "team:t2", "team:t3", "team:t4", "team:t5", "team:t6",
		"team:t7", "team:t8", "team:t9", "team:t10", "team:t11", "team:t12",
		"team:t13", "team:t14", "team:t15", "team:t16", "team:t17", "team:t18",
		"team:t19", "team:t20", "team:t21", "team:t22", "team:t23", "team:t24",
		"team:t25", "team:t26", "team:t27", "team:t28", "team:t29", "team:t30",
		uint8(8),
		"org:o1", "org:o2", "org:o3", "org:o4", "org:o5", "org:o6",
		"org:o7", "org:o8", "org:o9", "org:o10", "org:o11", "org:o12",
		"org:o13", "org:o14", "org:o15", "org:o16", "org:o17", "org:o18",
		"org:o19", "org:o20", "org:o21", "org:o22", "org:o23", "org:o24",
		"org:o25", "org:o26", "org:o27", "org:o28", "org:o29", "org:o30")

	// Seed 6: Complex folder with owner and viewer
	f.Add("model\n  schema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype folder\n  relations\n    define parent: [folder]\n    define owner: [user, group#member]\n    define viewer: [user, group#member] or owner or viewer from parent",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"folder:f1", "folder:f2", "folder:f3", "folder:f4", "folder:f5", "folder:f6",
		"folder:f7", "folder:f8", "folder:f9", "folder:f10", "folder:f11", "folder:f12",
		"folder:f13", "folder:f14", "folder:f15", "folder:f16", "folder:f17", "folder:f18",
		"folder:f19", "folder:f20", "folder:f21", "folder:f22", "folder:f23", "folder:f24",
		"folder:f25", "folder:f26", "folder:f27", "folder:f28", "folder:f29", "folder:f30",
		uint8(25),
		"folder:p1", "folder:p2", "folder:p3", "folder:p4", "folder:p5", "folder:p6",
		"folder:p7", "folder:p8", "folder:p9", "folder:p10", "folder:p11", "folder:p12",
		"folder:p13", "folder:p14", "folder:p15", "folder:p16", "folder:p17", "folder:p18",
		"folder:p19", "folder:p20", "folder:p21", "folder:p22", "folder:p23", "folder:p24",
		"folder:p25", "folder:p26", "folder:p27", "folder:p28", "folder:p29", "folder:p30")

	// Seed 7: Repository with multiple relations
	f.Add("model\n  schema 1.1\ntype user\ntype repo\n  relations\n    define admin: [user]\n    define writer: [user] or admin\n    define reader: [user] or writer",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"repo:r1", "repo:r2", "repo:r3", "repo:r4", "repo:r5", "repo:r6",
		"repo:r7", "repo:r8", "repo:r9", "repo:r10", "repo:r11", "repo:r12",
		"repo:r13", "repo:r14", "repo:r15", "repo:r16", "repo:r17", "repo:r18",
		"repo:r19", "repo:r20", "repo:r21", "repo:r22", "repo:r23", "repo:r24",
		"repo:r25", "repo:r26", "repo:r27", "repo:r28", "repo:r29", "repo:r30",
		uint8(18),
		"user:admin1", "user:admin2", "user:admin3", "user:admin4", "user:admin5", "user:admin6",
		"user:admin7", "user:admin8", "user:admin9", "user:admin10", "user:admin11", "user:admin12",
		"user:admin13", "user:admin14", "user:admin15", "user:admin16", "user:admin17", "user:admin18",
		"user:admin19", "user:admin20", "user:admin21", "user:admin22", "user:admin23", "user:admin24",
		"user:admin25", "user:admin26", "user:admin27", "user:admin28", "user:admin29", "user:admin30")

	// Seed 8: Simple role-based access
	f.Add("model\n  schema 1.1\ntype user\ntype role\n  relations\n    define assignee: [user]\ntype resource\n  relations\n    define role: [role]\n    define viewer: assignee from role",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"resource:r1", "resource:r2", "resource:r3", "resource:r4", "resource:r5", "resource:r6",
		"resource:r7", "resource:r8", "resource:r9", "resource:r10", "resource:r11", "resource:r12",
		"resource:r13", "resource:r14", "resource:r15", "resource:r16", "resource:r17", "resource:r18",
		"resource:r19", "resource:r20", "resource:r21", "resource:r22", "resource:r23", "resource:r24",
		"resource:r25", "resource:r26", "resource:r27", "resource:r28", "resource:r29", "resource:r30",
		uint8(14),
		"role:role1", "role:role2", "role:role3", "role:role4", "role:role5", "role:role6",
		"role:role7", "role:role8", "role:role9", "role:role10", "role:role11", "role:role12",
		"role:role13", "role:role14", "role:role15", "role:role16", "role:role17", "role:role18",
		"role:role19", "role:role20", "role:role21", "role:role22", "role:role23", "role:role24",
		"role:role25", "role:role26", "role:role27", "role:role28", "role:role29", "role:role30")

	// Seed 9: Workspace with channel relations
	f.Add("model\n  schema 1.1\ntype user\ntype workspace\n  relations\n    define member: [user]\ntype channel\n  relations\n    define workspace: [workspace]\n    define member: [user] or member from workspace",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"channel:c1", "channel:c2", "channel:c3", "channel:c4", "channel:c5", "channel:c6",
		"channel:c7", "channel:c8", "channel:c9", "channel:c10", "channel:c11", "channel:c12",
		"channel:c13", "channel:c14", "channel:c15", "channel:c16", "channel:c17", "channel:c18",
		"channel:c19", "channel:c20", "channel:c21", "channel:c22", "channel:c23", "channel:c24",
		"channel:c25", "channel:c26", "channel:c27", "channel:c28", "channel:c29", "channel:c30",
		uint8(22),
		"workspace:w1", "workspace:w2", "workspace:w3", "workspace:w4", "workspace:w5", "workspace:w6",
		"workspace:w7", "workspace:w8", "workspace:w9", "workspace:w10", "workspace:w11", "workspace:w12",
		"workspace:w13", "workspace:w14", "workspace:w15", "workspace:w16", "workspace:w17", "workspace:w18",
		"workspace:w19", "workspace:w20", "workspace:w21", "workspace:w22", "workspace:w23", "workspace:w24",
		"workspace:w25", "workspace:w26", "workspace:w27", "workspace:w28", "workspace:w29", "workspace:w30")

	// Seed 10: Project with task relations
	f.Add("model\n  schema 1.1\ntype user\ntype project\n  relations\n    define owner: [user]\n    define member: [user] or owner\ntype task\n  relations\n    define project: [project]\n    define viewer: [user] or member from project",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"task:t1", "task:t2", "task:t3", "task:t4", "task:t5", "task:t6",
		"task:t7", "task:t8", "task:t9", "task:t10", "task:t11", "task:t12",
		"task:t13", "task:t14", "task:t15", "task:t16", "task:t17", "task:t18",
		"task:t19", "task:t20", "task:t21", "task:t22", "task:t23", "task:t24",
		"task:t25", "task:t26", "task:t27", "task:t28", "task:t29", "task:t30",
		uint8(16),
		"project:p1", "project:p2", "project:p3", "project:p4", "project:p5", "project:p6",
		"project:p7", "project:p8", "project:p9", "project:p10", "project:p11", "project:p12",
		"project:p13", "project:p14", "project:p15", "project:p16", "project:p17", "project:p18",
		"project:p19", "project:p20", "project:p21", "project:p22", "project:p23", "project:p24",
		"project:p25", "project:p26", "project:p27", "project:p28", "project:p29", "project:p30")

	// Seed 11: Simple shared resource
	f.Add("model\n  schema 1.1\ntype user\ntype file\n  relations\n    define shared_with: [user]\n    define owner: [user]\n    define viewer: [user] or shared_with or owner",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"file:f1", "file:f2", "file:f3", "file:f4", "file:f5", "file:f6",
		"file:f7", "file:f8", "file:f9", "file:f10", "file:f11", "file:f12",
		"file:f13", "file:f14", "file:f15", "file:f16", "file:f17", "file:f18",
		"file:f19", "file:f20", "file:f21", "file:f22", "file:f23", "file:f24",
		"file:f25", "file:f26", "file:f27", "file:f28", "file:f29", "file:f30",
		uint8(11),
		"user:owner1", "user:owner2", "user:owner3", "user:owner4", "user:owner5", "user:owner6",
		"user:owner7", "user:owner8", "user:owner9", "user:owner10", "user:owner11", "user:owner12",
		"user:owner13", "user:owner14", "user:owner15", "user:owner16", "user:owner17", "user:owner18",
		"user:owner19", "user:owner20", "user:owner21", "user:owner22", "user:owner23", "user:owner24",
		"user:owner25", "user:owner26", "user:owner27", "user:owner28", "user:owner29", "user:owner30")

	// Seed 12: Board with list relations
	f.Add("model\n  schema 1.1\ntype user\ntype board\n  relations\n    define member: [user]\ntype list\n  relations\n    define board: [board]\n    define viewer: [user] or member from board",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"list:l1", "list:l2", "list:l3", "list:l4", "list:l5", "list:l6",
		"list:l7", "list:l8", "list:l9", "list:l10", "list:l11", "list:l12",
		"list:l13", "list:l14", "list:l15", "list:l16", "list:l17", "list:l18",
		"list:l19", "list:l20", "list:l21", "list:l22", "list:l23", "list:l24",
		"list:l25", "list:l26", "list:l27", "list:l28", "list:l29", "list:l30",
		uint8(9),
		"board:b1", "board:b2", "board:b3", "board:b4", "board:b5", "board:b6",
		"board:b7", "board:b8", "board:b9", "board:b10", "board:b11", "board:b12",
		"board:b13", "board:b14", "board:b15", "board:b16", "board:b17", "board:b18",
		"board:b19", "board:b20", "board:b21", "board:b22", "board:b23", "board:b24",
		"board:b25", "board:b26", "board:b27", "board:b28", "board:b29", "board:b30")

	// Seed 13: Account with permissions
	f.Add("model\n  schema 1.1\ntype user\ntype account\n  relations\n    define admin: [user]\n    define manager: [user]\n    define viewer: [user] or manager or admin",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"account:a1", "account:a2", "account:a3", "account:a4", "account:a5", "account:a6",
		"account:a7", "account:a8", "account:a9", "account:a10", "account:a11", "account:a12",
		"account:a13", "account:a14", "account:a15", "account:a16", "account:a17", "account:a18",
		"account:a19", "account:a20", "account:a21", "account:a22", "account:a23", "account:a24",
		"account:a25", "account:a26", "account:a27", "account:a28", "account:a29", "account:a30",
		uint8(13),
		"user:admin1", "user:admin2", "user:admin3", "user:admin4", "user:admin5", "user:admin6",
		"user:admin7", "user:admin8", "user:admin9", "user:admin10", "user:admin11", "user:admin12",
		"user:admin13", "user:admin14", "user:admin15", "user:admin16", "user:admin17", "user:admin18",
		"user:admin19", "user:admin20", "user:admin21", "user:admin22", "user:admin23", "user:admin24",
		"user:admin25", "user:admin26", "user:admin27", "user:admin28", "user:admin29", "user:admin30")

	// Seed 14: Service with endpoint permissions
	f.Add("model\n  schema 1.1\ntype user\ntype service\n  relations\n    define operator: [user]\ntype endpoint\n  relations\n    define service: [service]\n    define caller: [user] or operator from service",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"endpoint:e1", "endpoint:e2", "endpoint:e3", "endpoint:e4", "endpoint:e5", "endpoint:e6",
		"endpoint:e7", "endpoint:e8", "endpoint:e9", "endpoint:e10", "endpoint:e11", "endpoint:e12",
		"endpoint:e13", "endpoint:e14", "endpoint:e15", "endpoint:e16", "endpoint:e17", "endpoint:e18",
		"endpoint:e19", "endpoint:e20", "endpoint:e21", "endpoint:e22", "endpoint:e23", "endpoint:e24",
		"endpoint:e25", "endpoint:e26", "endpoint:e27", "endpoint:e28", "endpoint:e29", "endpoint:e30",
		uint8(7),
		"service:s1", "service:s2", "service:s3", "service:s4", "service:s5", "service:s6",
		"service:s7", "service:s8", "service:s9", "service:s10", "service:s11", "service:s12",
		"service:s13", "service:s14", "service:s15", "service:s16", "service:s17", "service:s18",
		"service:s19", "service:s20", "service:s21", "service:s22", "service:s23", "service:s24",
		"service:s25", "service:s26", "service:s27", "service:s28", "service:s29", "service:s30")

	// Seed 15: Container with nested objects
	f.Add("model\n  schema 1.1\ntype user\ntype container\n  relations\n    define parent: [container]\n    define viewer: [user] or viewer from parent\ntype object\n  relations\n    define container: [container]\n    define viewer: [user] or viewer from container",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"object:o1", "object:o2", "object:o3", "object:o4", "object:o5", "object:o6",
		"object:o7", "object:o8", "object:o9", "object:o10", "object:o11", "object:o12",
		"object:o13", "object:o14", "object:o15", "object:o16", "object:o17", "object:o18",
		"object:o19", "object:o20", "object:o21", "object:o22", "object:o23", "object:o24",
		"object:o25", "object:o26", "object:o27", "object:o28", "object:o29", "object:o30",
		uint8(19),
		"container:c1", "container:c2", "container:c3", "container:c4", "container:c5", "container:c6",
		"container:c7", "container:c8", "container:c9", "container:c10", "container:c11", "container:c12",
		"container:c13", "container:c14", "container:c15", "container:c16", "container:c17", "container:c18",
		"container:c19", "container:c20", "container:c21", "container:c22", "container:c23", "container:c24",
		"container:c25", "container:c26", "container:c27", "container:c28", "container:c29", "container:c30")

	// Seed 16: Department hierarchy
	f.Add("model\n  schema 1.1\ntype user\ntype company\n  relations\n    define employee: [user]\ntype department\n  relations\n    define company: [company]\n    define employee: [user] or employee from company",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"department:d1", "department:d2", "department:d3", "department:d4", "department:d5", "department:d6",
		"department:d7", "department:d8", "department:d9", "department:d10", "department:d11", "department:d12",
		"department:d13", "department:d14", "department:d15", "department:d16", "department:d17", "department:d18",
		"department:d19", "department:d20", "department:d21", "department:d22", "department:d23", "department:d24",
		"department:d25", "department:d26", "department:d27", "department:d28", "department:d29", "department:d30",
		uint8(17),
		"company:c1", "company:c2", "company:c3", "company:c4", "company:c5", "company:c6",
		"company:c7", "company:c8", "company:c9", "company:c10", "company:c11", "company:c12",
		"company:c13", "company:c14", "company:c15", "company:c16", "company:c17", "company:c18",
		"company:c19", "company:c20", "company:c21", "company:c22", "company:c23", "company:c24",
		"company:c25", "company:c26", "company:c27", "company:c28", "company:c29", "company:c30")

	// Seed 17: Drive with shared folders
	f.Add("model\n  schema 1.1\ntype user\ntype drive\n  relations\n    define owner: [user]\ntype folder\n  relations\n    define drive: [drive]\n    define parent: [folder]\n    define viewer: [user] or owner from drive or viewer from parent",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"folder:f1", "folder:f2", "folder:f3", "folder:f4", "folder:f5", "folder:f6",
		"folder:f7", "folder:f8", "folder:f9", "folder:f10", "folder:f11", "folder:f12",
		"folder:f13", "folder:f14", "folder:f15", "folder:f16", "folder:f17", "folder:f18",
		"folder:f19", "folder:f20", "folder:f21", "folder:f22", "folder:f23", "folder:f24",
		"folder:f25", "folder:f26", "folder:f27", "folder:f28", "folder:f29", "folder:f30",
		uint8(21),
		"drive:d1", "drive:d2", "drive:d3", "drive:d4", "drive:d5", "drive:d6",
		"drive:d7", "drive:d8", "drive:d9", "drive:d10", "drive:d11", "drive:d12",
		"drive:d13", "drive:d14", "drive:d15", "drive:d16", "drive:d17", "drive:d18",
		"drive:d19", "drive:d20", "drive:d21", "drive:d22", "drive:d23", "drive:d24",
		"drive:d25", "drive:d26", "drive:d27", "drive:d28", "drive:d29", "drive:d30")

	// Seed 18: API key permissions
	f.Add("model\n  schema 1.1\ntype user\ntype api_key\n  relations\n    define owner: [user]\ntype resource\n  relations\n    define api_key: [api_key]\n    define accessor: owner from api_key",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"resource:r1", "resource:r2", "resource:r3", "resource:r4", "resource:r5", "resource:r6",
		"resource:r7", "resource:r8", "resource:r9", "resource:r10", "resource:r11", "resource:r12",
		"resource:r13", "resource:r14", "resource:r15", "resource:r16", "resource:r17", "resource:r18",
		"resource:r19", "resource:r20", "resource:r21", "resource:r22", "resource:r23", "resource:r24",
		"resource:r25", "resource:r26", "resource:r27", "resource:r28", "resource:r29", "resource:r30",
		uint8(6),
		"api_key:k1", "api_key:k2", "api_key:k3", "api_key:k4", "api_key:k5", "api_key:k6",
		"api_key:k7", "api_key:k8", "api_key:k9", "api_key:k10", "api_key:k11", "api_key:k12",
		"api_key:k13", "api_key:k14", "api_key:k15", "api_key:k16", "api_key:k17", "api_key:k18",
		"api_key:k19", "api_key:k20", "api_key:k21", "api_key:k22", "api_key:k23", "api_key:k24",
		"api_key:k25", "api_key:k26", "api_key:k27", "api_key:k28", "api_key:k29", "api_key:k30")

	// Seed 19: Multi-tenant application
	f.Add("model\n  schema 1.1\ntype user\ntype tenant\n  relations\n    define admin: [user]\n    define member: [user] or admin\ntype app\n  relations\n    define tenant: [tenant]\n    define viewer: [user] or member from tenant",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"app:a1", "app:a2", "app:a3", "app:a4", "app:a5", "app:a6",
		"app:a7", "app:a8", "app:a9", "app:a10", "app:a11", "app:a12",
		"app:a13", "app:a14", "app:a15", "app:a16", "app:a17", "app:a18",
		"app:a19", "app:a20", "app:a21", "app:a22", "app:a23", "app:a24",
		"app:a25", "app:a26", "app:a27", "app:a28", "app:a29", "app:a30",
		uint8(5),
		"tenant:t1", "tenant:t2", "tenant:t3", "tenant:t4", "tenant:t5", "tenant:t6",
		"tenant:t7", "tenant:t8", "tenant:t9", "tenant:t10", "tenant:t11", "tenant:t12",
		"tenant:t13", "tenant:t14", "tenant:t15", "tenant:t16", "tenant:t17", "tenant:t18",
		"tenant:t19", "tenant:t20", "tenant:t21", "tenant:t22", "tenant:t23", "tenant:t24",
		"tenant:t25", "tenant:t26", "tenant:t27", "tenant:t28", "tenant:t29", "tenant:t30")

	// Seed 20: Network with device permissions
	f.Add("model\n  schema 1.1\ntype user\ntype network\n  relations\n    define admin: [user]\ntype device\n  relations\n    define network: [network]\n    define operator: [user] or admin from network",
		"user:alice", "user:bob", "user:charlie", "user:dave", "user:eve", "user:frank",
		"user:grace", "user:heidi", "user:ivan", "user:judy", "user:karl", "user:lisa",
		"user:mike", "user:nancy", "user:oscar", "user:peggy", "user:quinn", "user:robert",
		"user:sara", "user:trent", "user:ursula", "user:victor", "user:wendy", "user:xavier",
		"user:yvonne", "user:zach", "user:amy", "user:ben", "user:claire", "user:dan",
		"device:d1", "device:d2", "device:d3", "device:d4", "device:d5", "device:d6",
		"device:d7", "device:d8", "device:d9", "device:d10", "device:d11", "device:d12",
		"device:d13", "device:d14", "device:d15", "device:d16", "device:d17", "device:d18",
		"device:d19", "device:d20", "device:d21", "device:d22", "device:d23", "device:d24",
		"device:d25", "device:d26", "device:d27", "device:d28", "device:d29", "device:d30",
		uint8(30),
		"network:n1", "network:n2", "network:n3", "network:n4", "network:n5", "network:n6",
		"network:n7", "network:n8", "network:n9", "network:n10", "network:n11", "network:n12",
		"network:n13", "network:n14", "network:n15", "network:n16", "network:n17", "network:n18",
		"network:n19", "network:n20", "network:n21", "network:n22", "network:n23", "network:n24",
		"network:n25", "network:n26", "network:n27", "network:n28", "network:n29", "network:n30")

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

		srv := server.MustNewServerWithOpts(server.WithDatastore(datastore))
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
