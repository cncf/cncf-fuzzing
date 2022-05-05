package server

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/containers/storage/pkg/idtools"
	"os"
)

func FuzzgetDecryptionKeys(data []byte) int {
	keysPath := "/tmp/keysPath"
	err := os.MkdirAll(keysPath, 0777)
	if err != nil {
		return 0
	}
	defer os.RemoveAll(keysPath)
	f := fuzz.NewConsumer(data)
	err = f.CreateFiles(keysPath)
	if err != nil {
		return 0
	}
	return 1
}

func FuzzIdtoolsParseIDMap(data []byte) int {
	f := fuzz.NewConsumer(data)
	mapSec := make([]string, 0)
	err := f.CreateSlice(&mapSec)
	if err != nil {
		return 0
	}
	mapSetting, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = idtools.ParseIDMap(mapSec, mapSetting)
	return 1
}
