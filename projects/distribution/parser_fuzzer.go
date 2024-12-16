//go:build gofuzz
// +build gofuzz

package configuration

import (
	"bytes"
	"os"
	"testing"
)

// ParserFuzzer implements a fuzzer that targets Parser()
// Export before building
// nolint:deadcode
func parserFuzzer(f *testing.F) {
	f.Fuzz(func(t *testing.T, rdData []byte, envKey, envValue string) {
		os.Setenv(envKey, envValue)
		defer os.Unsetenv(envKey)
		rd := bytes.NewReader(rdData)
		_, _ = Parse(rd)
	})
}
