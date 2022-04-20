package storage

import (
	"github.com/containers/image/v5/transports/alltransports"	
)

func FuzzParseImageName(data []byte) int {
	_, _ = alltransports.ParseImageName(string(data))
	return 1
}