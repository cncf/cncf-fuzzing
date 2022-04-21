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
	"time"

	libmock "github.com/cri-o/cri-o/test/mocks/lib"

	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/AdaLogics/go-fuzz-headers/sanitizers/logsanitizer"
	cstorage "github.com/containers/storage"
	"github.com/golang/mock/gomock"
	_ "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/streaming"

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
	t                 *testing.T
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
)

const (
	sandboxID   = "sandboxID"
	containerID = "containerID"
)

func init() {
	t = &testing.T{}
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
}

func setupLogSanitizer() (*logsanitizer.Sanitizer, *os.File, error) {
	logFile, err := os.Create(logFileAbs)
	if err != nil {
		return nil, nil, err
	}
	logrus.SetOutput(logFile)

	logSanitizer := logsanitizer.NewSanitizer()
	logSanitizer.SetLogFile(logFileAbs)
	logSanitizer.AddInsecureStrings("INFOFUZZ[0027] Starting container:", "DEBUFUZZ[0027]")
	return logSanitizer, logFile, nil
}

func runLogSanitizer(logSAN *logsanitizer.Sanitizer, logFp *os.File) {
	logSAN.CheckLogfile()
	logFp.Close()
	os.Remove(logFileAbs)
}

func FuzzServer(data []byte) int {
	logSAN, logFp, err := setupLogSanitizer()
	if err != nil {
		panic(err)
	}

	defer runLogSanitizer(logSAN, logFp)

	if len(data) < 50 {
		return 0
	}

	f := fuzz.NewConsumer(data)
	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfCalls%10; i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType % 25 {

		// Server calls listed alphabetically relative to their RPC calls
		// https://github.com/cri-o/cri-o/tree/main/server/cri/v1alpha2
		// rpc_attach
		case 0:
			req := &types.AttachRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.Attach(context.Background(), req)
		case 1:
			req := &types.ContainerStatsRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ContainerStats(context.Background(), req)
		case 2:
			req := &types.ContainerStatusRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ContainerStatus(context.Background(), req)
		case 3:
			req := &types.CreateContainerRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.CreateContainer(context.Background(), req)
		case 4:
			req := &types.ExecRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.Exec(context.Background(), req)
		case 5:
			req := &types.ExecSyncRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ExecSync(context.Background(), req)
		case 6:

			//req := &types.ImageFsInfoResponse{}
			//err = f.GenerateStruct(req)
			//if err != nil {
			//  return 0
			// }
			// _, _ = sut.ImageFsInfo(context.Background(), req)
		case 7:
			// Currently not supported

			/*req := &types.ImageStatusRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ImageStatus(context.Background(), req)*/
		case 8:
			req := &types.ListContainerStatsRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ListContainerStats(context.Background(), req)
		case 9:
			req := &types.ListContainersRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ListContainers(context.Background(), req)
		case 10:
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
				_, _ = sut.ListPodSandbox(context.Background(), req)
			} else {
				sb, sandboxID, c, err := createSandbox(f)
				if err != nil {
					return 0
				}
				defer c()
				err = sut.AddSandbox(sb)
				if err != nil {
					return 0
				}
				sb.SetCreated()
				_, err = sut.LoadSandbox(context.Background(), sandboxID)
				if err == nil {
					_, _ = sut.ListPodSandbox(context.Background(),
						&types.ListPodSandboxRequest{Filter: &types.PodSandboxFilter{
							Id: sandboxID,
						}})
				}
			}
		case 11:
			req := &types.ListPodSandboxStatsRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.ListPodSandboxStats(context.Background(), req)
		case 12:
			req := &types.PodSandboxStatsRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.PodSandboxStats(context.Background(), req)
		case 13:
			req := &types.PodSandboxStatusRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.PodSandboxStatus(context.Background(), req)
		case 14:
			req := &types.PortForwardRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_, _ = sut.PortForward(context.Background(), req)
		case 15:
			//req := &types.PullImageRequest{}
			//err := f.GenerateStruct(req)
			//if err != nil {
			//	return 0
			//}
			//fmt.Print("15\n")
			//_, _ = sut.PullImage(context.Background(), req)
		case 16:
			req := &types.RemoveContainerRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.RemoveContainer(context.Background(), req)
		case 17:
			req := &types.RemovePodSandboxRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.RemovePodSandbox(context.Background(), req)
		case 18:
			req := &types.ReopenContainerLogRequest{}
			err := f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.ReopenContainerLog(context.Background(), req)
		case 19:
			//req := &types.RunPodSandboxRequest{}
			//err = f.GenerateStruct(req)
			//if err != nil {
			//	return 0
			//}
			//_, _ = sut.RunPodSandbox(context.Background(), req)
		case 20:
			req := &types.StartContainerRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.StartContainer(context.Background(), req)
		case 21:
		//	req := &types.StatusRequest{}
		//	err = f.GenerateStruct(req)
		//		if err != nil {
		//			return 0
		//	}
		//_, _ = sut.Status(context.Background(), req)
		case 22:
			req := &types.StopContainerRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.StopContainer(context.Background(), req)
		case 23:
			req := &types.StopPodSandboxRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.StopPodSandbox(context.Background(), req)
		case 24:
			req := &types.UpdateContainerResourcesRequest{}
			err = f.GenerateStruct(req)
			if err != nil {
				return 0
			}
			_ = sut.UpdateContainerResources(context.Background(), req)
		}
	}
	return 1
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
	logDir := "/tmp/logPath"
	err = os.MkdirAll(logDir, 0750)
	if err != nil && !os.IsExist(err) {
		return nil, "", nilFunc, err
	}
	shmPath := "/tmp/shmPath"
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
	processLabel, err := f.GetString()
	if err != nil {
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
	resolvPath := "/tmp/dirPath"
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
