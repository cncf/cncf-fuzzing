package blockio

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

	randomFile, err := os.Create("blockio_fuzz.config")
	if err != nil {
		return 0
	}
	defer os.Remove("blockio_fuzz.config")

	_, err = randomFile.Write(confBytes)
	if err != nil {
		randomFile.Close()
		return 0
	}

	c.Load("blockio_fuzz.config")
	randomFile.Close()

	return 1
}
