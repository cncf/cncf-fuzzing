// Copyright 2022 ADA Logics Ltd
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

package operators

import (
	"vitess.io/vitess/go/vt/sqlparser"
	"vitess.io/vitess/go/vt/vtgate/semantics"
	"vitess.io/vitess/go/vt/vtgate/planbuilder/plancontext"
)

// FuzzAnalyse implements the fuzzer
func FuzzAnalyse(data []byte) int {
	tree, err := sqlparser.NewTestParser().Parse(string(data))
	if err != nil {
		return -1
	}
	semTable, err := semantics.Analyze(tree, "", &semantics.FakeSI{})
	if err != nil {
		return 0
	}
	ctx := &plancontext.PlanningContext{
                           SemTable:     semTable,
        }
	_ = translateQueryToOp(ctx, tree)	
	/*switch stmt := tree.(type) {
	case *sqlparser.Select:
		semTable, err := semantics.Analyze(stmt, "", &semantics.FakeSI{})
		if err != nil {
			return 0
		}
		ctx := &plancontext.PlanningContext{
                            SemTable:     semTable,
                }
		_ = createOperatorFromSelect(ctx, stmt)

	default:
		return 0
	}*/
	return 1
}
