package utils

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzGeneratePasswd(data []byte) int {
	etcDir := "/tmp/etcDir"
	err := os.MkdirAll(etcDir, 0777)
	if err != nil {
		return 0
	}
	defer os.RemoveAll(etcDir)
	f := fuzz.NewConsumer(data)
	err = f.CreateFiles(etcDir)
	if err != nil {
		return 0
	}
	uid, gid, _, err := GetUserInfo(etcDir, "root")
	if err != nil {
		return 0
	}
	username, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = GeneratePasswd(username, uid, gid, "", etcDir, etcDir)

	return 1
}
