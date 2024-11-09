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

package lane

import (
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/golang/mock/gomock"
	"github.com/kubeedge/beehive/pkg/core/model"
	"github.com/kubeedge/kubeedge/pkg/viaduct/mocks"
	"github.com/kubeedge/kubeedge/pkg/viaduct/pkg/packer"
	"github.com/kubeedge/kubeedge/pkg/viaduct/pkg/translator"
)

var mockFuzzStream *mocks.MockStream
var errorFuzzReturn error

// initMocks is function to initialize mocks.
func initMocksForFuzzing(t *FuzzTester) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockFuzzStream = mocks.NewMockStream(mockCtrl)
}

func FuzzLaneReadMessage(data []byte) int {
	f := fuzz.NewConsumer(data)
	msg := &model.Message{}
	err := f.GenerateStruct(msg)
	if err != nil {
		return 0
	}

	bytesMsg, err := translator.NewTran().Encode(msg)
	if err != nil {
		return 0
	}

	header := packer.PackageHeader{Version: 0011, PayloadLen: (uint32(len(bytesMsg)))}
	headerBuffer := make([]byte, 0)
	header.Pack(&headerBuffer)

	t := &FuzzTester{}
	initMocksForFuzzing(t)

	l := &QuicLane{
		stream: mockFuzzStream,
	}
	mockFuzzStream.EXPECT().Read(gomock.Any()).Return(0, errorFuzzReturn).Times(0)
	callFirst := mockFuzzStream.EXPECT().Read(gomock.Any()).SetArg(0, headerBuffer).Return(packer.HeaderSize, nil).Times(1)
	mockFuzzStream.EXPECT().Read(gomock.Any()).SetArg(0, bytesMsg).Return(len(bytesMsg), nil).Times(1).After(callFirst)
	err = l.ReadMessage(msg)
	if err != nil {
	}
	return 1
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
