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

package fuzzing

import (
	"vitess.io/vitess/go/vt/vttablet/tabletserver/rules"
)

func FuzzUnmarshalJSON(data []byte) int {
	qrs := rules.New()
	err := qrs.UnmarshalJSON(data)
	if err != nil {
		return 0
	}
	// Exercise more rule methods
	_ = qrs.Copy()
	_, _ = qrs.MarshalJSON()
	// Test Equal with a copy
	cp := qrs.Copy()
	_ = qrs.Equal(cp)
	return 1
}
