package apparmor

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzLoadConfig(data []byte) int {
	c := Config{}
	c.enabled = true

	f := fuzz.NewConsumer(data)
	confBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}

	randomFile, err := os.Create("apparmor_fuzz.config")
	if err != nil {
		return 0
	}
	defer os.Remove("apparmor_fuzz.config")

	_, err = randomFile.Write(confBytes)
	if err != nil {
		randomFile.Close()
		return 0
	}

	c.LoadProfile("apparmor_fuzz.config")
	randomFile.Close()

	return 1
}
