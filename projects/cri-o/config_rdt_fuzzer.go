package rdt

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzLoadConfig(data []byte) int {
	c := Config{}
	c.enabled = true
	c.supported = true

	f := fuzz.NewConsumer(data)
	confBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}

	randomFile, err := os.Create("rdt_fuzz.config")
	if err != nil {
		return 0
	}
	defer os.Remove("rdt_fuzz.config")

	_, err = randomFile.Write(confBytes)
	if err != nil {
		randomFile.Close()
		return 0
	}

	c.Load("rdt_fuzz.config")
	randomFile.Close()

	return 1
}
