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

package profiles

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzProfilesValidate(data []byte) int {
	_ = Validate(data)
	return 1
}

func FuzzRenderProto(data []byte) int {
	f := fuzz.NewConsumer(data)
	protodata, err := f.GetBytes()
	if err != nil {
		return 0
	}
	namespace, err := f.GetString()
	if err != nil {
		return 0
	}
	name, err := f.GetString()
	if err != nil {
		return 0
	}
	clusterDomain, err := f.GetString()
	if err != nil {
		return 0
	}
	protofile, err := os.Create("protofile")
	if err != nil {
		return 0
	}
	defer protofile.Close()
	defer os.Remove(protofile.Name())

	_, err = protofile.Write(protodata)
	if err != nil {
		return 0
	}
	w, err := os.OpenFile("/dev/null", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0
	}
	defer w.Close()
	_ = RenderProto(protofile.Name(), namespace, name, clusterDomain, w)
	return 1
}
