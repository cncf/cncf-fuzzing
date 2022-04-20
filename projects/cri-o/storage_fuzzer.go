package storage

import (
	"os"
	"github.com/containers/image/v5/types"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/pkg/shortnames"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzParseImageName(data []byte) int {
	_, _ = alltransports.ParseImageName(string(data))
	return 1
}

func FuzzShortnamesResolve(data []byte) int {
	f := fuzz.NewConsumer(data)
	confBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	name, err := f.GetString()
	if err != nil {
		return 0
	}
	confFile, err := os.Create("registries.conf")
	if err != nil {
		return 0
	}
	defer os.Remove("registries.conf")
	_, err = confFile.Write(confBytes)
	if err != nil {
		return 0
	}

	ctx := &types.SystemContext{
					SystemRegistriesConfPath: "registries.conf",
				}
	_, _ = shortnames.Resolve(ctx, name)
	return 1
}