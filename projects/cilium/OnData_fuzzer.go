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

package cassandra

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/proxy/proxylib/accesslog"
	"github.com/cilium/proxy/proxylib/proxylib"
	"github.com/cilium/proxy/proxylib/test"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/sirupsen/logrus"
)

var (
	s       *CassandraSuite
	parsers = []string{"cassandra", "kafka", "r2d2", "memcache"}

	ErrInvalidBytes       = errors.New("Invalid bytes")
	ErrCouldNotCreateData = errors.New("Could not create test data")
	ErrInvalidParserData  = errors.New("Invalid parser-specific data")
)

func init() {
	s = &CassandraSuite{}
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	logrus.SetLevel(logrus.PanicLevel)
	proxylib.LogFatal = func(format string, args ...interface{}) {
		fmt.Sprintf(format, args...)
	}
}

// Sets the parser type
func getParser(index int) string {
	return parsers[index%len(parsers)]
}

// Creates the test data from the byte slice
func createData(f *fuzz.ConsumeFuzzer) (string, []string, [][]byte, bool, string, error) {
	// Empty return values
	version := ""
	policies := make([]string, 0)
	d := make([][]byte, 0)
	reply := false
	parser := ""
	err := ErrCouldNotCreateData

	// Create the data
	version, err = f.GetString()
	if err != nil {
		return version, policies, d, reply, parser, err
	}

	err = f.CreateSlice(&policies)
	if err != nil {
		return version, policies, d, reply, parser, err
	}

	err = f.CreateSlice(&d)
	if err != nil {
		return version, policies, d, reply, parser, err
	}

	reply, err = f.GetBool()
	if err != nil {
		return version, policies, d, reply, parser, err
	}

	parserType, err := f.GetInt()
	if err != nil {
		return version, policies, d, reply, parser, err
	}
	parser = getParser(parserType)
	return version, policies, d, reply, parser, nil
}

// The cassandra bytes are validated later in the calltree.
// Doing the same validation now improves performance.
func verifyCassandraBytes(d [][]byte) error {
	testD := bytes.Join(d, []byte{})
	if len(testD) < 10 {
		return ErrInvalidBytes
	}
	requestLen := binary.BigEndian.Uint32(testD[5:9])
	if requestLen > cassMaxLen {
		return ErrInvalidBytes
	}
	return nil
}

func verifyr2d2Bytes(d [][]byte) error {
	testD := string(bytes.Join(d, []byte{}))
	msgLen := strings.Index(testD, "\r\n")
	if msgLen < 0 {
		return ErrInvalidBytes
	}
	msgStr := testD[:msgLen] // read single request
	fields := strings.Split(msgStr, " ")
	if len(fields) < 1 {
		return ErrInvalidBytes
	}
	return nil
}

func verifyParserData(parser string, d [][]byte, reply bool) error {
	if parser == "cassandra" {
		err := verifyCassandraBytes(d)
		if err != nil {
			return ErrInvalidParserData
		}
	}

	if parser == "r2d2" {
		// Could consider setting reply here instead of checking it
		if reply == true {
			return ErrInvalidParserData
		}
		err := verifyr2d2Bytes(d)
		if err != nil {
			return ErrInvalidParserData
		}
	}

	if parser == "kafka" {
		// Could consider setting reply here instead of checking it
		if reply == true {
			return ErrInvalidParserData
		}
	}

	return nil
}

// FuzzMultipleParsers implements the fuzzer
func FuzzMultipleParsers(data []byte) int {
	f := fuzz.NewConsumer(data)

	version, policies, d, reply, parser, err := createData(f)
	if err != nil {
		return 0
	}

	err = verifyParserData(parser, d, reply)
	if err != nil {
		return 0
	}

	defer s.logServer.Clear()
	err = s.ins.InsertPolicyText(version, policies, "")
	if err != nil {
		return 0
	}

	bufSize := 1024
	origBuf := make([]byte, 0, bufSize)
	replyBuf := make([]byte, 0, bufSize)

	err, conn := proxylib.NewConnection(s.ins, parser, 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy", &origBuf, &replyBuf)
	if err != nil {
		return 0
	}
	ops := make([][2]int64, 0, 100)
	conn.OnData(reply, false, &d, &ops)
	return 1
}
