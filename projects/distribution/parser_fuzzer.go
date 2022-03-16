// +build gofuzz

package configuration

import (
        "bytes"
        "os"
        fuzz "github.com/AdaLogics/go-fuzz-headers"
)

// ParserFuzzer implements a fuzzer that targets Parser()
// Export before building
// nolint:deadcode
func parserFuzzer(data []byte) int {
        f := fuzz.NewConsumer(data)
        rdData, err := f.GetBytes()
        if err != nil {
                return 0
        }
        envKey, err := f.GetString()
        if err != nil {
                return 0
        }
        envValue, err := f.GetString()
        if err != nil {
                return 0
        }
        os.Setenv(envKey, envValue)
        defer os.Unsetenv(envKey)
        rd := bytes.NewReader(rdData)
        _, _ = Parse(rd)
        return 1
}