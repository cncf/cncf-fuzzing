//go:build gofuzz
// +build gofuzz

package intelrdt

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func FuzzParseMonFeatures(data []byte) int {
	_, _ = parseMonFeatures(strings.NewReader(string(data)))
	return 1
}

func FuzzSetCacheScema(data []byte) int {
	if len(data)%2 != 0 {
		return -1
	}
	half := len(data) / 2
	dir, err := os.MkdirTemp("", "intelrdt-fuzz-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)
	resctrl := filepath.Join(dir, "resctrl")
	if err := os.MkdirAll(resctrl, 0o755); err != nil {
		return 0
	}
	before := append([]byte{}, data[:half]...)
	before = append(before, '\n')
	if err := os.WriteFile(filepath.Join(resctrl, "schemata"), before, 0o644); err != nil {
		return 0
	}
	config := &configs.Config{IntelRdt: &configs.IntelRdt{
		L3CacheSchema: string(data[half:]),
	}}
	oldRoot := root
	root = func() (string, error) {
		return resctrl, nil
	}
	defer func() {
		root = oldRoot
	}()
	_ = NewManager(config, "", resctrl).Set(config)
	return 1
}
