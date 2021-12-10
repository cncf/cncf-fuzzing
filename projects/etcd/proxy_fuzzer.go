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

package proxy

import (
	"net/url"
	"os"
	"testing"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	"go.uber.org/zap"
)

func init() {
	testing.Init()
}

var fuzzLogger = zap.NewExample()

func FuzzProxyServer(data []byte) int {
	t := &testing.T{}
	scheme := "unix"
	srcAddr, dstAddr := newUnixAddr(), newUnixAddr()
	defer func() {
		os.RemoveAll(srcAddr)
		os.RemoveAll(dstAddr)
	}()
	tlsInfo := transport.TLSInfo{}
	ln := listen(t, scheme, dstAddr, transport.TLSInfo{})
	defer ln.Close()

	p := NewServer(ServerConfig{
		Logger: fuzzLogger,
		From:   url.URL{Scheme: scheme, Host: srcAddr},
		To:     url.URL{Scheme: scheme, Host: dstAddr},
	})
	<-p.Ready()
	defer p.Close()

	send(t, data, scheme, srcAddr, tlsInfo)
	return 1
}
