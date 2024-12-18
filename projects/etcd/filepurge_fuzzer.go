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

package fileutil

import (
	"os"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/zap"
)

func FuzzPurgeFile(data []byte) int {
	dir, err := os.MkdirTemp("", "purgefile")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	f := fuzz.NewConsumer(data)

	err = f.CreateFiles(dir)
	if err != nil {
		return 0
	}

	stop, purgec := make(chan struct{}), make(chan string, 10)

	// keep 3 most recent files
	_ = purgeFile(zap.NewExample(), dir, "test", 3, time.Millisecond, stop, purgec, nil, false)
	return 1
}
