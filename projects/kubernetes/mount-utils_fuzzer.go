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

// place in kubernetes/staging/src/k8s.io/mount-utils
package mount
  
import (
        "io/ioutil"
        "os"
)

func FuzzSearchMountPoints(data []byte) int {
        tmpFile, err := ioutil.TempFile("", "test-get-filetype")
        if err != nil {
                panic(err)
        }
        defer os.Remove(tmpFile.Name())
        defer tmpFile.Close()
        tmpFile.Truncate(0)
        tmpFile.Seek(0, 0)
        tmpFile.WriteString(string(data))
        tmpFile.Sync()
        _, _ = SearchMountPoints("/mnt/disks/vol1", tmpFile.Name())
        return 1
}
