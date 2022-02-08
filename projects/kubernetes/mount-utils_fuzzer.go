// place in kubernetes/staging/src/k8s.io/mount-utils
package mount
  
import (
        "io/ioutil"
        "os"
)

func Fuzz(data []byte) int {
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
