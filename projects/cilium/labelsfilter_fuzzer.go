// Copyright 2023 ADA Logics Ltd
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

package labelsfilter

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cilium/cilium/pkg/labels"
)

func FuzzLabelsfilterPkg(data []byte) int {
	f := fuzz.NewConsumer(data)

	prefixes := make([]string, 0)
	err := f.CreateSlice(&prefixes)
	if err != nil {
		return 0
	}
	lpc := &labelPrefixCfg{}
	err = f.GenerateStruct(lpc)
	if err != nil {
		return 0
	}
	lpc.Version = LPCfgFileVersion
	fileBytes, err := json.Marshal(lpc)

	if err != nil {
		return 0
	}
	stringMap := make(map[string]string)
	err = f.FuzzMap(&stringMap)
	if err != nil {
		return 0
	}

	source, err := f.GetString()
	if err != nil {
		return 0
	}

	lbls := labels.Map2Labels(stringMap, source)

	file, err := os.Create("file")
	defer file.Close()
	if err != nil {
		return 0
	}

	_, err = file.Write(fileBytes)
	if err != nil {
		return 0
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = ParseLabelPrefixCfg(logger, prefixes, nil, "file")
	if err != nil {
		fmt.Println(err)
		return 0
	}
	_, _ = Filter(lbls)
	return 1
}
