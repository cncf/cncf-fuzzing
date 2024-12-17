package container

import (
	"context"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cri-o/cri-o/internal/hostport"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	oci "github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/internal/storage"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func FuzzContainer(data []byte) int {
	// Main config
	sut, err := New()
	if err != nil {
		return 0
	}

	f := fuzz.NewConsumer(data)

	// Create random configs
	sandboxConfig := &types.PodSandboxConfig{}
	f.GenerateStruct(sandboxConfig)
	containerConfig := &types.ContainerConfig{}
	f.GenerateStruct(containerConfig)

	// Initialize the config with random data
	if err = sut.SetConfig(containerConfig, sandboxConfig); err != nil {
		return 1
	}

	// Perform a set of operations on the config. Abort if error
	logPath, err := f.GetString()
	if err != nil {
		return 1
	}

	_, err = sut.LogPath(logPath)
	if err != nil {
		return 1
	}

	sboxLabel, err := f.GetString()
	if err != nil {
		return 1
	}

	_, err = sut.SelinuxLabel(sboxLabel)
	if err != nil {
		return 1
	}

	var m map[string]string
	err = f.FuzzMap(&m)
	if err != nil {
		return 1
	}

	err = sut.AddUnifiedResourcesFromAnnotations(m)
	if err != nil {
		return 1
	}

	// Call into SpecAddAnnotations
	currentTime := time.Now()
	sb, err := sandbox.New("sandboxID", "", "", "", "test",
		make(map[string]string), make(map[string]string), "", "",
		&types.PodSandboxMetadata{}, "", "", false, "", "", "",
		[]*hostport.PortMapping{}, false, currentTime, "", nil, nil)

	if err != nil {
		return 1
	}

	volumes := []oci.ContainerVolume{}
	mountPoint := "test"
	configStopSignal := "test"
	imageResult := storage.ImageResult{}

	err = sut.SpecAddAnnotations(context.Background(), sb, volumes, mountPoint, configStopSignal, &imageResult, false, "", "")
	if err != nil {
		return 1
	}

	err = sut.SpecAddDevices(nil, nil, false, false)
	if err != nil {
		return 1
	}

	return 1
}
