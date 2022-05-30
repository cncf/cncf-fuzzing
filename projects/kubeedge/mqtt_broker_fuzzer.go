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

package mqtt

import (
	"fmt"
	"time"

	"github.com/256dpi/gomqtt/broker"
	"github.com/256dpi/gomqtt/client"
	"github.com/256dpi/gomqtt/packet"
	"github.com/256dpi/gomqtt/transport"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzMqttPublish(data []byte) int {
	f := fuzz.NewConsumer(data)
	var topic string
	customString, err := f.GetBool()
	if err != nil {
		return 0
	}
	if customString {
		topic, err = f.GetString()
		if err != nil {
			return 0
		}
	} else {
		topic = "test"
	}
	payload, err := f.GetBytes()
	if err != nil {
		return 0
	}
	server, err := transport.Launch("tcp://localhost:8080")
	if err != nil {
		return 0
	}

	done := make(chan struct{})

	backend := broker.NewMemoryBackend()
	backend.Logger = func(e broker.LogEvent, c *broker.Client, pkt packet.Generic, msg *packet.Message, err error) {
		if e == broker.LostConnection {
			close(done)
		}
	}

	engine := broker.NewEngine(backend)
	engine.Accept(server)

	c := client.New()
	wait := make(chan struct{})

	c.Callback = func(msg *packet.Message, err error) error {
		if err != nil {
			return fmt.Errorf("CallBack error %s", err.Error())
		}
		close(wait)
		return nil
	}

	cf, err := c.Connect(client.NewConfig("tcp://localhost:8080"))
	if err != nil {
		return 0
	}

	err = cf.Wait(10 * time.Second)
	if err != nil {
		return 0
	}

	sf, err := c.Subscribe(topic, 0)
	if err != nil {
		return 0
	}

	err = sf.Wait(10 * time.Second)
	if err != nil {
		return 0
	}

	pf, err := c.Publish(topic, payload, 0, false)
	if err != nil {
		return 0
	}

	err = pf.Wait(10 * time.Second)
	if err != nil {
		return 0
	}

	<-wait

	err = c.Disconnect()
	if err != nil {
		return 0
	}

	<-done

	err = server.Close()
	if err != nil {
		return 0
	}

	engine.Close()
	return 1
}
