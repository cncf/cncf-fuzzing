// Copyright 2023 the cncf-fuzzing authors
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

package websocket

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	stdTesting "testing"

	"github.com/gorilla/websocket"
	ktesting "knative.dev/pkg/logging/testing"
)

func FuzzSendRawMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		spy := &inspectableConnection{
			writeMessageCalls: make(chan struct{}, 1),
		}

		conn := newConnection(staticConnFactory(spy), nil)
		conn.connect()

		if got := conn.Status(); got != nil {
			t.Skip()
		}

		if got := conn.SendRaw(websocket.BinaryMessage, data); got != nil {
			t.Skip()
		}
		if len(spy.writeMessageCalls) != 1 {
			t.Fatalf("Expected 'WriteMessage' to be called once, but was called %v times", spy.writeMessageCalls)
		}
	})
}

func FuzzDurableConnection(f *testing.F) {
	f.Fuzz(func(t *testing.T, testPayload string, data []byte) {
		reconnectChan := make(chan struct{})

		upgrader := websocket.Upgrader{}
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}

			// Waits for a message to be sent before dropping the connection.
			<-reconnectChan
			c.Close()
		}))
		defer s.Close()

		logger := ktesting.TestLogger(&stdTesting.T{})
		target := "ws" + strings.TrimPrefix(s.URL, "http")
		conn := NewDurableSendingConnection(target, logger)
		defer conn.Shutdown()
		if err := conn.Send(testPayload); err != nil {
			return
		}
		if got := conn.SendRaw(websocket.BinaryMessage, data); got != nil {
			return
		}

		// Message successfully sent, instruct the server to drop the connection.
		reconnectChan <- struct{}{}
	})

}

func FuzzReceiveMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, testMessage string) {
		spy := &inspectableConnection{
			writeMessageCalls: make(chan struct{}, 1),
			nextReaderCalls:   make(chan struct{}, 1),
			nextReaderFunc: func() (int, io.Reader, error) {
				return websocket.TextMessage, strings.NewReader(testMessage), nil
			},
		}

		messageChan := make(chan []byte, 1)
		conn := newConnection(staticConnFactory(spy), messageChan)
		conn.connect()
		go conn.keepalive()

		got := <-messageChan

		if string(got) != testMessage {
			panic(fmt.Sprintf("Received the wrong message, wanted %q, got %q\n", testMessage, string(got)))
		}
	})
}
