/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ssh_probe

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

// DatadogLogs Datadog logs forwarder
type DatadogLogs struct {
	wg        *sync.WaitGroup
	stop      chan struct{}
	EventChan chan interface{}
	conn      net.Conn
}

// Start sets up communication with the Datadog agent
func (dl *DatadogLogs) Start(agentURL string) error {
	dl.wg = &sync.WaitGroup{}
	dl.EventChan = make(chan interface{}, 1000)
	dl.stop = make(chan struct{})

	if agentURL == "" {
		return nil
	}

	// Prepare connection with the agent
	var err error
	dl.conn, err = net.Dial("udp", agentURL)
	if err != nil {
		return fmt.Errorf("couldn't connect to the agent: %v", err)
	}
	go dl.listen()
	return nil
}

// listen waits for events and sends them
func (dl *DatadogLogs) listen() {
	dl.wg.Add(1)
	var event interface{}
	var ok bool
	for {
		select {
		case <-dl.stop:
			dl.wg.Done()
			return
		case event, ok = <-dl.EventChan:
			if !ok {
				dl.wg.Done()
				return
			}
			// Send to Datadog
			data, err := json.Marshal(event)
			if err != nil {
				logrus.Errorf("couldn't marshal event: %v", err)
				continue
			}
			if _, err := dl.conn.Write(data); err != nil {
				logrus.Errorf("couldn't send event to the agent: %v", err)
			}
		}
	}
}

// Stop stops the logs forwarder
func (dl *DatadogLogs) Stop() error {
	close(dl.stop)
	close(dl.EventChan)
	dl.wg.Wait()
	return nil
}
