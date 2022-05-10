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

package server

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	libmock "github.com/cri-o/cri-o/test/mocks/lib"

	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/AdaLogics/go-fuzz-headers/sanitizers/logsanitizer"
	cstorage "github.com/containers/storage"
	"github.com/golang/mock/gomock"
	_ "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/streaming"

	"github.com/cri-o/cri-o/internal/hostport"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/oci"
	"github.com/cri-o/cri-o/pkg/config"
	//"github.com/cri-o/cri-o/internal/resourcestore"
	"github.com/cri-o/cri-o/internal/storage"
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
	testStreamService StreamService
	testSandbox       *sandbox.Sandbox
	testContainer     *oci.Container
	sut               *Server
	imageServerMock   *criostoragemock.MockImageServer
	runtimeServerMock *criostoragemock.MockRuntimeServer
	cniPluginMock     *ocicnitypesmock.MockCNIPlugin
	logFileAbs        = "/tmp/cri-o-logfile"
	initter           sync.Once
	debugging         = false
	ci                storage.ContainerInfo
	f                 *fuzz.ConsumeFuzzer

	rpcCalls = map[int]string{
		0:  "Attach",
		1:  "ContainerStats",
		2:  "ContainerStatus",
		3:  "CreateContainer",
		4:  "Exec",
		5:  "ExecSync",
		6:  "ImageFsInfo",
		7:  "ImageStatus",
		8:  "ListContainerStats",
		9:  "ListContainers",
		10: "ListPodSandbox",
		11: "ListPodSandboxStats",
		12: "PodSandboxStats",
		13: "PodSandboxStatus",
		14: "PortForward",
		15: "PullImage",
		16: "RemoveContainer",
		17: "RemovePodSandbox",
		18: "ReopenContainerLog",
		19: "RunPodSandbox",
		20: "StartContainer",
		21: "Status",
		22: "StopContainer",
		23: "StopPodSandbox",
		24: "UpdateContainerResources",
		25: "AddContainer", // Not an rpc call
		26: "ListImages",
	}
)

const (
	sandboxID   = "sandboxID"
	containerID = "containerID"
)

func initFunc() {
	//t1 = &testing.T{}
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
	err := beforeEachFuzz()
	if err != nil {
		panic(err)
	}
	mockNewServer()

	sut, err = New(context.Background(), libMock)
	if err != nil {
		panic(err)
	}
	cniPluginMock.EXPECT().Status().Return(nil)
	err = sut.SetCNIPlugin(cniPluginMock)
	if err != nil {
		panic(err)
	}
	sut.SetStorageImageServer(imageServerMock)
	sut.SetStorageRuntimeServer(runtimeServerMock)
}

func FuzzedContainerInfo() (func(), error) {
	// Create Dir and RunDir
	custom, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-", 5)
	if err != nil {
		return func() {}, err
	}
	runDir := "/tmp/" + custom

	custom, err = f.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-", 5)
	if err != nil {
		return func() {}, err
	}
	dir := "/tmp/" + custom

	c := func() {
		os.RemoveAll(runDir)
		os.RemoveAll(dir)
	}
	err = os.MkdirAll(dir, 0777)
	if err != nil {
		return c, err
	}
	err = os.MkdirAll(runDir, 0777)
	if err != nil {
		return c, err
	}

	// Create labels
	id, err := f.GetString()
	if err != nil {
		return c, err
	}
	// Create structured string, because otherwise CRI-o cannot delete
	// the sandbox because of this check: https://github.com/cri-o/cri-o/blob/main/vendor/github.com/opencontainers/selinux/go-selinux/selinux_linux.go#L743
	var b strings.Builder
	processLabel1, err := f.GetString()
	if err != nil {
		return c, err
	}
	processLabel2, err := f.GetString()
	if err != nil {
		return c, err
	}
	processLabel3, err := f.GetString()
	if err != nil {
		return c, err
	}
	processLabel4, err := f.GetString()
	if err != nil {
		return c, err
	}
	b.WriteString(processLabel1)
	b.WriteString(":")
	b.WriteString(processLabel2)
	b.WriteString(":")
	b.WriteString(processLabel3)
	b.WriteString(":")
	b.WriteString(processLabel4)
	processLabel := b.String()
	con := strings.SplitN(processLabel, ":", 4)
	if len(con) < 3 {
		return c, err
	}
	mountLabel, err := f.GetString()
	if err != nil {
		return c, err
	}
	gomock.InOrder(
		runtimeServerMock.EXPECT().CreatePodSandbox(gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).
			Return(storage.ContainerInfo{
				ID:           id,
				Dir:          dir,
				RunDir:       runDir,
				Config:       &v1.Image{Config: v1.ImageConfig{}},
				ProcessLabel: processLabel,
				MountLabel:   mountLabel,
			}, nil),
		runtimeServerMock.EXPECT().DeleteContainer(gomock.Any()).
			Return(nil),
	)
	return c, nil
}

func nonLogSANInit() {
	initFunc()
	logrus.SetLevel(logrus.FatalLevel)

}

// Same as FuzzServer but with logSAN
func FuzzServerLogSAN(data []byte) int {
	initter.Do(nonLogSANInit)
	if len(data) < 50 {
		return 0
	}
	logSAN, err := logsanitizer.SetupLogSANForLogrus(logFileAbs)
	if err != nil {
		panic(err)
	}
	defer logSAN.RunSanitizer()
	return fuzzServer(data)
}

func FuzzServer(data []byte) int {
	initter.Do(nonLogSANInit)
	if len(data) < 50 {
		return 0
	}
	return fuzzServer(data)
}

func fuzzServer(data []byte) int {
	printCall(fmt.Sprintf("---------- New iteration ----------"))
	defer catchPanics()
	defer func() {
		// Remove all containers up containers
		resp, err := sut.ListContainers(context.Background(), &types.ListContainersRequest{})
		if err == nil {
			for _, c := range resp.Containers {
				removeRequest := &types.RemoveContainerRequest{
					ContainerId: c.Id,
				}
				_ = sut.RemoveContainer(context.Background(), removeRequest)
			}
		} else {
			panic(err)
		}
		resp, err = sut.ListContainers(context.Background(), &types.ListContainersRequest{})
		if err != nil {
			panic(err)
		} else if len(resp.Containers) != 0 {
			panic("Not all containers were deleted during cleanup")
		}
		// Remove all sandboxes
		sandboxes := sut.ListSandboxes()
		for _, sb := range sandboxes {
			sut.RemoveSandbox(sb.ID())
		}
		if len(sut.ListSandboxes()) != 0 {
			panic("Not all sandboxes were deleted during cleanup")
		}
	}()

	f = fuzz.NewConsumer(data)
	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfCalls%10; i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		rpcCall := rpcCalls[callType%len(rpcCalls)]
		switch rpcCall {

		// Server calls listed alphabetically relative to their RPC calls
		// https://github.com/cri-o/cri-o/tree/main/server/cri/v1alpha2
		// rpc_attach
		case "Attach":
			req := &types.AttachRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.Attach(context.Background(), req)
		case "ContainerStats":
			req := &types.ContainerStatsRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ContainerStats(context.Background(), req)
		case "ContainerStatus":
			req := &types.ContainerStatusRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ContainerStatus(context.Background(), req)
		case "CreateContainer":
			req := &types.CreateContainerRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.CreateContainer(context.Background(), req)
		case "Exec":
			req := &types.ExecRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.Exec(context.Background(), req)
		case "ExecSync":
			req := &types.ExecSyncRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ExecSync(context.Background(), req)
		case "ImageFsInfo":
			printCall(rpcCall)
			_, _ = sut.ImageFsInfo(context.Background())
		case "ImageStatus":
			req := &types.ImageStatusRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ImageStatus(context.Background(), req)
		case "ListContainerStats":
			req := &types.ListContainerStatsRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ListContainerStats(context.Background(), req)
		case "ListContainers":
			req := &types.ListContainersRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ListContainers(context.Background(), req)
		case "ListPodSandbox":
			completelyRandom, err := f.GetBool()
			if err != nil {
				return 0
			}
			if completelyRandom {
				req := &types.ListPodSandboxRequest{}
				err = f.GenerateStruct(req)
				if err != nil {
					return 0
				}
				printCall(fmt.Sprintf("%s (completelyRandom): \nRequest: %+v\n", rpcCall, req))
				_, _ = sut.ListPodSandbox(context.Background(), req)
			} else {
				sb, sandboxID, c, err := createSandbox(f)
				if err != nil {
					return 0
				}
				defer c()
				err = sut.AddSandbox(sb)
				if err != nil {
					fmt.Println(err)
					return 0
				}
				sb.SetCreated()
				_, err = sut.LoadSandbox(context.Background(), sandboxID)
				if err == nil {
					printCall(fmt.Sprintf("%s (not completelyRandom)", rpcCall))
					_, _ = sut.ListPodSandbox(context.Background(),
						&types.ListPodSandboxRequest{Filter: &types.PodSandboxFilter{
							Id: sandboxID,
						}})
				}
			}
		case "ListPodSandboxStats":
			req := &types.ListPodSandboxStatsRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ListPodSandboxStats(context.Background(), req)
		case "PodSandboxStats":
			req := &types.PodSandboxStatsRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.PodSandboxStats(context.Background(), req)
		case "PodSandboxStatus":
			req := &types.PodSandboxStatusRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(rpcCall)
			_, _ = sut.PodSandboxStatus(context.Background(), req)
		case "PortForward":
			req := &types.PortForwardRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.PortForward(context.Background(), req)
		case "PullImage":
			//req := &types.PullImageRequest{}
			//err := f.GenerateStruct(req)
			//if err != nil {
			//	return 0
			//}
			//fmt.Print("15\n")
			//_, _ = sut.PullImage(context.Background(), req)
		case "RemoveContainer":
			req := &types.RemoveContainerRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.RemoveContainer(context.Background(), req)
		case "RemovePodSandbox":
			req := &types.RemovePodSandboxRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.RemovePodSandbox(context.Background(), req)
		case "ReopenContainerLog":
			req := &types.ReopenContainerLogRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.ReopenContainerLog(context.Background(), req)
		case "RunPodSandbox":
			req := &types.RunPodSandboxRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}

			// Do some basic checks on the request
			req.RuntimeHandler = ""

			if req.Config == nil {
				continue
			}
			if req.Config.Metadata == nil || req.Config.Metadata.Name == "" {
				continue
			}

			// create the log dir
			custom, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-", 20)
			if err != nil {
				return 0
			}
			logDirectory := "/tmp/" + custom

			err = os.MkdirAll(logDirectory, 0777)
			if err != nil {
				return 0
			}
			defer func() {
				os.RemoveAll(logDirectory)
			}()
			req.Config.LogDirectory = logDirectory

			// set up the CreatePodSandbox call
			cleanupFunc, err := FuzzedContainerInfo()
			defer cleanupFunc()
			if err != nil {
				return 0
			}

			// Specify deadlie to not fall into timeouts because
			// cri-o is retrying for minutes.
			shortDuration := 550 * time.Millisecond
			d := time.Now().Add(shortDuration)
			ctx, _ := context.WithDeadline(context.Background(), d)
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.RunPodSandbox(ctx, req)
		case "StartContainer":
			req := &types.StartContainerRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.StartContainer(context.Background(), req)
		case "Status":
			req := &types.StatusRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.Status(context.Background(), req)
		case "StopContainer":
			req := &types.StopContainerRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.StopContainer(context.Background(), req)
		case "StopPodSandbox":
			req := &types.StopPodSandboxRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.StopPodSandbox(context.Background(), req)
		case "UpdateContainerResources":
			req := &types.UpdateContainerResourcesRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_ = sut.UpdateContainerResources(context.Background(), req)
		case "AddContainer":
			// Not an RPC call, but it is helpful to have this included.

			// First check if any sandboxes exist. If not, then it is a
			// waste to proceed, since we need one to succesfully create
			// a container
			sandboxes := sut.ListSandboxes()
			if len(sandboxes) == 0 {
				continue
			}

			newContainer, err := createContainer(f, sandboxes)
			if err != nil {
				continue
			}
			sut.AddContainer(newContainer)
		case "ListImages":
			req := &types.ListImagesRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			printCall(fmt.Sprintf("%s: \nRequest: %+v\n", rpcCall, req))
			_, _ = sut.ListImages(context.Background(), req)
		}
	}
	return 1
}

func createContainer(f *fuzz.ConsumeFuzzer, sandboxes []*sandbox.Sandbox) (*oci.Container, error) {
	id, err := f.GetString()
	if err != nil {
		return nil, err
	}
	name, err := f.GetString()
	if err != nil {
		return nil, err
	}
	bundlePath, err := f.GetString()
	if err != nil {
		return nil, err
	}
	logPath, err := f.GetString()
	if err != nil {
		return nil, err
	}
	labels := make(map[string]string)
	err = f.FuzzMap(&labels)
	if err != nil {
		return nil, err
	}
	crioAnnotations := make(map[string]string)
	err = f.FuzzMap(&crioAnnotations)
	if err != nil {
		return nil, err
	}
	annotations := make(map[string]string)
	err = f.FuzzMap(&annotations)
	if err != nil {
		return nil, err
	}
	image, err := f.GetString()
	if err != nil {
		return nil, err
	}
	imageName, err := f.GetString()
	if err != nil {
		return nil, err
	}
	imageRef, err := f.GetString()
	if err != nil {
		return nil, err
	}
	metadata := &types.ContainerMetadata{}
	err = f.GenerateStruct(metadata)
	if err != nil {
		return nil, err
	}

	// Get a name of a sanbox that exists
	sbIndex, err := f.GetInt()
	if err != nil {
		return nil, err
	}
	sandbox := sandboxes[sbIndex%len(sandboxes)].ID()
	terminal := false
	stdin := false
	stdinOnce := false
	runtimeHandler := ""
	dir, err := f.GetString()
	if err != nil {
		return nil, err
	}
	created := time.Now()
	stopSignal, err := f.GetString()
	if err != nil {
		return nil, err
	}
	return oci.NewContainer(id, name, bundlePath, logPath, labels,
		crioAnnotations, annotations, image,
		imageName, imageRef, metadata, sandbox,
		terminal, stdin, stdinOnce, runtimeHandler,
		dir, created, stopSignal)
}

func printCall(rpcCall string) {
	if debugging {
		fmt.Printf("Calling: ")
		fmt.Println(rpcCall)
	}
}

func mockNewServer() {
	gomock.InOrder(
		libMock.EXPECT().GetData().Times(2).Return(serverConfig),
		libMock.EXPECT().GetStore().Return(storeMock, nil),
		libMock.EXPECT().GetData().Return(serverConfig),
		storeMock.EXPECT().Containers().
			Return([]cstorage.Container{}, nil),
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

	// Initialize test streaming server
	streamServerConfig := streaming.DefaultConfig
	testStreamService = StreamService{}
	testStreamService.SetRuntimeServerFuzz(sut)
	server, err := streaming.NewServer(streamServerConfig, testStreamService)
	if err != nil {
		return err
	}
	if server == nil {
		return fmt.Errorf("streaming server is nil")
	}
	return nil
}

func (s *StreamService) SetRuntimeServerFuzz(server *Server) {
	s.runtimeServer = server
}

func createSandbox(f *fuzz.ConsumeFuzzer) (*sandbox.Sandbox, string, func(), error) {
	nilFunc := func() {
		return
	}
	sandboxIDFuzz, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	name, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	custom, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-", 5)
	if err != nil {
		return nil, "", nilFunc, err
	}
	logDir := filepath.Join("tmp", custom, "logPath")
	err = os.MkdirAll(logDir, 0750)
	if err != nil && !os.IsExist(err) {
		return nil, "", nilFunc, err
	}
	custom, err = f.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-", 5)
	if err != nil {
		return nil, "", nilFunc, err
	}
	shmPath := filepath.Join("tmp", custom, "shmPath")
	err = os.MkdirAll(shmPath, 0750)
	if err != nil && !os.IsExist(err) {
		return nil, "", nilFunc, err
	}
	kubeName, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	labels := make(map[string]string)
	err = f.FuzzMap(&labels)
	if err != nil {
		return nil, "", nilFunc, err
	}
	annotations := make(map[string]string)
	err = f.FuzzMap(&annotations)
	if err != nil {
		return nil, "", nilFunc, err
	}
	// Create structured string, because otherwise CRI-o cannot delete
	// the sandbox because of this check: https://github.com/cri-o/cri-o/blob/main/vendor/github.com/opencontainers/selinux/go-selinux/selinux_linux.go#L743
	var b strings.Builder
	processLabel1, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	processLabel2, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	processLabel3, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	processLabel4, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	b.WriteString(processLabel1)
	b.WriteString(":")
	b.WriteString(processLabel2)
	b.WriteString(":")
	b.WriteString(processLabel3)
	b.WriteString(":")
	b.WriteString(processLabel4)
	processLabel := b.String()
	con := strings.SplitN(processLabel, ":", 4)
	if len(con) < 3 {
		return nil, "", nilFunc, err
	}

	mountLabel, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	metadata := &types.PodSandboxMetadata{}
	err = f.GenerateStruct(metadata)
	if err != nil {
		return nil, "", nilFunc, err
	}
	cgroupParent, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	runtimeHandler, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	custom, err = f.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-", 5)
	if err != nil {
		return nil, "", nilFunc, err
	}
	resolvPath := filepath.Join("tmp", custom, "dirPath")
	err = os.MkdirAll(resolvPath, 0750)
	if err != nil && !os.IsExist(err) {
		return nil, "", nilFunc, err
	}
	hostName, err := f.GetString()
	if err != nil {
		return nil, "", nilFunc, err
	}
	created := time.Now()
	portMappings := make([]*hostport.PortMapping, 0)

	sb, err := sandbox.New(sandboxIDFuzz,
		"default",
		name,
		kubeName,
		logDir,
		labels,
		annotations,
		processLabel,
		mountLabel,
		metadata,
		shmPath,
		cgroupParent,
		false,
		runtimeHandler,
		resolvPath,
		hostName,
		portMappings,
		false,
		created,
		"")
	cancelFunc := func() {
		os.RemoveAll(shmPath)
		os.RemoveAll(logDir)
		os.RemoveAll(resolvPath)
	}
	return sb, sandboxIDFuzz, cancelFunc, err
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
	panic(fmt.Sprintf("Fatal panic from fuzzer: %s %+v\n", format, args))
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
