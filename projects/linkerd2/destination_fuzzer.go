// Copyright 2021 ADA Logics Ltd
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

package destination

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
	"github.com/linkerd/linkerd2/controller/api/destination/watcher"
	"github.com/linkerd/linkerd2/controller/api/util"
	sp "github.com/linkerd/linkerd2/controller/gen/apis/serviceprofile/v1alpha2"
	logging "github.com/sirupsen/logrus"
)

func init() {
	testing.Init()
}

func FuzzAdd(data []byte) int {
	f := fuzz.NewConsumer(data)
	set := watcher.AddressSet{}
	err := f.GenerateStruct(&set)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	_, translator := makeEndpointTranslator(t)
	translator.Add(set)
	translator.Remove(set)
	return 1
}

func FuzzGet(data []byte) int {
	f := fuzz.NewConsumer(data)
	dest1 := &pb.GetDestination{}
	err := f.GenerateStruct(dest1)
	if err != nil {
		return 0
	}
	dest2 := &pb.GetDestination{}
	err = f.GenerateStruct(dest2)
	if err != nil {
		return 0
	}
	dest3 := &pb.GetDestination{}
	err = f.GenerateStruct(dest3)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	server := makeServer(t)

	stream := &bufferingGetStream{
		updates:          []*pb.Update{},
		MockServerStream: util.NewMockServerStream(),
	}
	_ = server.Get(dest1, stream)
	_ = server.Get(dest2, stream)
	_ = server.Get(dest3, stream)
	return 1
}

func FuzzGetProfile(data []byte) int {
	f := fuzz.NewConsumer(data)
	dest := &pb.GetDestination{}
	err := f.GenerateStruct(dest)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	server := makeServer(t)
	stream := &bufferingGetProfileStream{
		updates:          []*pb.DestinationProfile{},
		MockServerStream: util.NewMockServerStream(),
	}
	stream.Cancel()
	_ = server.GetProfile(dest, stream)
	return 1
}

func FuzzProfileTranslatorUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	profile := &sp.ServiceProfile{}
	err := f.GenerateStruct(profile)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	mockGetProfileServer := &mockDestinationGetProfileServer{profilesReceived: []*pb.DestinationProfile{}}

	translator := &profileTranslator{
		stream: mockGetProfileServer,
		log:    logging.WithField("test", t.Name()),
	}
	translator.Update(profile)
	return 1
}
