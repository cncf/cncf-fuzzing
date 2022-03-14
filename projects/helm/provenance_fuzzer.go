package provenance

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzNewFromFiles(data []byte) int {
	f := fuzz.NewConsumer(data)
	keyFileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	keyFile, err := os.Create("keyFile")
	if err != nil {
		return 0
	}
	defer keyFile.Close()
	defer os.Remove(keyFile.Name())
	_, err = keyFile.Write(keyFileBytes)
	if err != nil {
		return 0
	}
	keyringFile, err := os.Create("keyringFile ")
	if err != nil {
		return 0
	}
	defer keyringFile.Close()
	defer os.Remove(keyringFile.Name())
	keyringFileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	_, err = keyringFile.Write(keyringFileBytes)
	if err != nil {
		return 0
	}
	_, _ = NewFromFiles(keyFile.Name(), keyringFile.Name())
	return 1
}

func FuzzParseMessageBlock(data []byte) int {
	_, _, _ = parseMessageBlock(data)
	return 1
}

func FuzzMessageBlock(data []byte) int {
	f := fuzz.NewConsumer(data)
	err := os.Mkdir("fuzzDir", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("fuzzDir")
	err = f.CreateFiles("fuzzDir")
	if err != nil {
		return 0
	}
	_, _ = messageBlock("fuzzDir")
	return 1
}
