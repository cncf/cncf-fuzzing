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

package container

func FuzzModifyImageRepository(data []byte) int {
	if len(data)%2 != 0 {
		return 0
	}
	imageName := string(data[:len(data)/2])
	repositoryName := string(data[len(data)/2:])
	_, _ = ModifyImageRepository(imageName, repositoryName)
	return 1
}
func FuzzModifyImageTag(data []byte) int {
	if len(data)%2 != 0 {
		return 0
	}
	imageName := string(data[:len(data)/2])
	repositoryName := string(data[len(data)/2:])
	_, _ = ModifyImageTag(imageName, repositoryName)
	return 1
}
