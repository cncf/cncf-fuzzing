package config

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/sirupsen/logrus"
	"os"
)

func FuzzLoadConfig(data []byte) int {
	logrus.SetLevel(logrus.ErrorLevel)

	c, err := DefaultConfig()
	if err != nil {
		return 0
	}

	f := fuzz.NewConsumer(data)
	confBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}

	randomFile, err := os.Create("cri-o.config")
	if err != nil {
		return 0
	}
	defer os.Remove("cri-o.config")

	_, err = randomFile.Write(confBytes)
	if err != nil {
		randomFile.Close()
		return 0
	}

	if err = c.UpdateFromFile("cri-o.config"); err != nil {
		randomFile.Close()
		return 0
	}

	if err = c.Validate(false); err != nil {
		randomFile.Close()
		return 0
	}

	devNullFile, err := os.Open(os.DevNull)
	if err != nil {
		randomFile.Close()
		return 0
	}

	if err = c.WriteTemplate(true, devNullFile); err != nil {
		return 0
	}

	randomFile.Close()
	devNullFile.Close()

	return 1
}
