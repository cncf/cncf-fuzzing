// Copyright 2021 ADA Logics Ltd
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

package intelrdt

import (
	"strings"
	"testing"
)

func init() {
	testing.Init()
}

func FuzzParseMonFeatures(data []byte) int {
	_, _ = parseMonFeatures(
		strings.NewReader(string(data)))
	return 1
}

func FuzzSetCacheScema(data []byte) int {
	t := &testing.T{}
	if (len(data) % 2) != 0 {
		return -1
	}
	halfLen := len(data) / 2
	firstHalf := data[:halfLen]
	secondHalf := data[halfLen:]

	helper := NewIntelRdtTestUtil(t)

	l3CacheSchemaBefore := string(firstHalf)
	l3CacheSchemeAfter := string(secondHalf)

	helper.writeFileContents(map[string]string{
		"schemata": l3CacheSchemaBefore + "\n",
	})

	helper.config.IntelRdt.L3CacheSchema = l3CacheSchemeAfter
	intelrdt := NewManager(helper.config, "", helper.IntelRdtPath)
	intelrdt.Set(helper.config)

	return 1
}