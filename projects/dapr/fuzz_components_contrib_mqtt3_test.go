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

package mqtt

import (
	"regexp"
	"testing"
)

func FuzzAddTopic(f *testing.F) {
	f.Fuzz(func(t *testing.T, origTopicName string) {
		m := &mqttPubSub{}
		m.topics = make(map[string]mqttPubSubSubscription)
		topicName := origTopicName
		if found := sharedSubscriptionMatch.FindStringIndex(origTopicName); found != nil && found[0] == 0 {
			topicName = topicName[(found[1] - 1):]
		}

		regexStr := buildRegexForTopic(topicName)
		if regexStr != "" {
			_, err := regexp.Compile(regexStr)
			if err != nil {
				return
			}
			m.addTopic(origTopicName, nil)
		}

	})
}
