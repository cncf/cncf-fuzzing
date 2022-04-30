// Copyright 2022 ADA Logics Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package lib

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	libmock "github.com/cri-o/cri-o/test/mocks/lib"

	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/golang/mock/gomock"
	_ "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/cri-o/cri-o/internal/hostport"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/pkg/config"
	containerstoragemock "github.com/cri-o/cri-o/test/mocks/containerstorage"
	criostoragemock "github.com/cri-o/cri-o/test/mocks/criostorage"
	ocicnitypesmock "github.com/cri-o/cri-o/test/mocks/ocicni"
)

var (
	libMock           *libmock.MockIface
	mockCtrl          *gomock.Controller
	storeMock         *containerstoragemock.MockStore
	serverConfig      *config.Config
	t1                *testing.T
	emptyDir          string
	testManifest      []byte
	testPath          string
	testSandbox       *sandbox.Sandbox
	testContainer     *oci.Container
	sut               *ContainerServer
	imageServerMock   *criostoragemock.MockImageServer
	runtimeServerMock *criostoragemock.MockRuntimeServer
	cniPluginMock     *ocicnitypesmock.MockCNIPlugin
	logFileAbs        = "/tmp/cri-o-logfile"
	initter           sync.Once
)

const (
	sandboxID   = "sandboxID"
	containerID = "containerID"
)

func FuzzContainerServer(data []byte) int {
	f := fuzz.NewConsumer(data)
	s1, err := f.GetString()
	if err != nil {
		return 0
	}

	s2, err := f.GetString()
	if err != nil {
		return 0
	}

	configBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}

	t := &FuzzTester{}
	mockCtrl = gomock.NewController(t)
	libMock = libmock.NewMockIface(mockCtrl)
	storeMock = containerstoragemock.NewMockStore(mockCtrl)
	imageServerMock = criostoragemock.NewMockImageServer(mockCtrl)
	runtimeServerMock = criostoragemock.NewMockRuntimeServer(mockCtrl)
	cniPluginMock = ocicnitypesmock.NewMockCNIPlugin(mockCtrl)

	// Manage log level:
	logrus.SetLevel(logrus.DebugLevel)

	// Set up the CRI-O server
	err = beforeEachFuzz()
	if err != nil {
		panic(err)
	}

	// Specify mocks
	gomock.InOrder(
		libMock.EXPECT().GetStore().Return(storeMock, nil),
		libMock.EXPECT().GetData().Return(serverConfig),
	)

	mockFuzzDirs(configBytes)

	sut, err = New(context.Background(), libMock)
	if err != nil {
		panic(err)
	}

	_, _ = sut.PodIDForName(s1)
	_, _ = sut.ReservePodName(s1, s2)
	_ = sut.HasContainer(s1)
	_ = sut.GetSandbox(s1)
	_ = sut.GetSandboxContainer(s2)

	// Let's call the LoadSandbox
	_, _ = sut.LoadSandbox(context.Background(), s2)

	return 1
}

func mockFuzzDirs(manifest []byte) {
	gomock.InOrder(
		storeMock.EXPECT().
			FromContainerDirectory(gomock.Any(), gomock.Any()).
			Return(manifest, nil),
		storeMock.EXPECT().ContainerRunDirectory(gomock.Any()).
			Return("", nil),
		storeMock.EXPECT().ContainerDirectory(gomock.Any()).
			Return("", nil),
	)
}

func beforeEachFuzz() error {
	testManifest = []byte(`{
                "annotations": {
                        "io.kubernetes.cri-o.Annotations": "{}",
                        "io.kubernetes.cri-o.ContainerID": "sandboxID",
                        "io.kubernetes.cri-o.ContainerName": "containerName",
                        "io.kubernetes.cri-o.ContainerType": "{}",
                        "io.kubernetes.cri-o.Created": "2006-01-02T15:04:05.999999999Z",
                        "io.kubernetes.cri-o.HostName": "{}",
                        "io.kubernetes.cri-o.CgroupParent": "{}",
                        "io.kubernetes.cri-o.IP": "{}",
                        "io.kubernetes.cri-o.NamespaceOptions": "{}",
                        "io.kubernetes.cri-o.SeccompProfilePath": "{}",
                        "io.kubernetes.cri-o.Image": "{}",
                        "io.kubernetes.cri-o.ImageName": "{}",
                        "io.kubernetes.cri-o.ImageRef": "{}",
                        "io.kubernetes.cri-o.KubeName": "{}",
                        "io.kubernetes.cri-o.PortMappings": "[]",
                        "io.kubernetes.cri-o.Labels": "{}",
                        "io.kubernetes.cri-o.LogPath": "{}",
                        "io.kubernetes.cri-o.Metadata": "{}",
                        "io.kubernetes.cri-o.Name": "name",
                        "io.kubernetes.cri-o.Namespace": "default",
                        "io.kubernetes.cri-o.PrivilegedRuntime": "{}",
                        "io.kubernetes.cri-o.ResolvPath": "{}",
                        "io.kubernetes.cri-o.HostnamePath": "{}",
                        "io.kubernetes.cri-o.SandboxID": "sandboxID",
                        "io.kubernetes.cri-o.SandboxName": "{}",
                        "io.kubernetes.cri-o.ShmPath": "{}",
                        "io.kubernetes.cri-o.MountPoint": "{}",
                        "io.kubernetes.cri-o.TrustedSandbox": "{}",
                        "io.kubernetes.cri-o.Stdin": "{}",
                        "io.kubernetes.cri-o.StdinOnce": "{}",
                        "io.kubernetes.cri-o.Volumes": "[{}]",
                        "io.kubernetes.cri-o.HostNetwork": "{}",
                        "io.kubernetes.cri-o.CNIResult": "{}"
                },
                "linux": {
                        "namespaces": [
                                {"type": "network", "path": "/proc/self/ns/net"}
                        ]
                },
                "process": {
                        "selinuxLabel": "system_u:system_r:container_runtime_t:s0"
                }}`)

	// Prepare the server config
	var err error
	testPath, err = filepath.Abs("test")
	if err != nil {
		return err
	}
	serverConfig, err = config.DefaultConfig()
	if err != nil {
		return err
	}
	serverConfig.ContainerAttachSocketDir = testPath
	serverConfig.ContainerExitsDir = path.Join(testPath, "exits")
	serverConfig.LogDir = path.Join(testPath, "log")
	serverConfig.CleanShutdownFile = path.Join(testPath, "clean.shutdown")

	serverConfig.NetworkDir = emptyDir
	serverConfig.PluginDirs = []string{emptyDir}
	serverConfig.HooksDir = []string{emptyDir}

	err = serverConfig.NetworkConfig.Validate(false)
	if err != nil {
		panic(err)
	}

	// Initialize test container and sandbox
	testSandbox, err = sandbox.New(sandboxID, "", "", "", "",
		make(map[string]string), make(map[string]string), "", "",
		&types.PodSandboxMetadata{}, "", "", false, "", "", "",
		[]*hostport.PortMapping{}, false, time.Now(), "")
	if err != nil {
		return err
	}

	testContainer, err = oci.NewContainer(containerID, "", "", "",
		make(map[string]string), make(map[string]string),
		make(map[string]string), "pauseImage", "", "",
		&types.ContainerMetadata{}, sandboxID, false, false,
		false, "", "", time.Now(), "")
	if err != nil {
		return err
	}

	return nil
}

type FuzzTester struct {
}

func (ft *FuzzTester) Cleanup(func())                            {}
func (ft *FuzzTester) Setenv(kev, value string)                  {}
func (ft *FuzzTester) Error(args ...interface{})                 {}
func (ft *FuzzTester) Errorf(format string, args ...interface{}) {}
func (ft *FuzzTester) Fail()                                     {}
func (ft *FuzzTester) FailNow()                                  {}
func (ft *FuzzTester) Failed() bool                              { return true }
func (ft *FuzzTester) Fatal(args ...interface{})                 { panic("Fatal panic from fuzzer") }
func (ft *FuzzTester) Fatalf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	fmt.Print("\n")
	panic("Fatal panic from fuzzer")
}
func (ft *FuzzTester) Helper()                                  {}
func (ft *FuzzTester) Log(args ...interface{})                  {}
func (ft *FuzzTester) Logf(format string, args ...interface{})  {}
func (ft *FuzzTester) Name() string                             { return "fuzz" }
func (ft *FuzzTester) Parallel()                                {}
func (ft *FuzzTester) Skip(args ...interface{})                 {}
func (ft *FuzzTester) SkipNow()                                 {}
func (ft *FuzzTester) Skipf(format string, args ...interface{}) {}
func (ft *FuzzTester) Skipped() bool                            { return true }
func (ft *FuzzTester) TempDir() string                          { return "/tmp" }

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "Fatal panic from fuzzer") {
			return
		} else {
			panic(err)
		}
	}
}
