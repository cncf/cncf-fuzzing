package websocket

import (
	"github.com/gorilla/websocket"
	"testing"
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
