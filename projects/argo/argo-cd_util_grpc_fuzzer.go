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

package grpc

import (
	"context"
	"runtime"
	"strings"

	"github.com/Masterminds/semver/v3"
	"google.golang.org/grpc/metadata"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

// We ignore these panics, as they don't represent real bugs.
func catchPanicsGrpcFuzzer() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "improper constraint") {
			return
		} else if strings.Contains(err, "constraint Parser Error") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzUserAgentUnaryServerInterceptor(data []byte) int {
	defer catchPanicsGrpcFuzzer()
	f := fuzz.NewConsumer(data)
	clientName, err := f.GetString()
	if err != nil {
		return 0
	}
	contraintStr, err := f.GetString()
	if err != nil {
		return 0
	}
	_ = UserAgentUnaryServerInterceptor(clientName, contraintStr)
	return 1
}

func FuzzuserAgentEnforcer(data []byte) int {
	clientName := "argo-cd"
	f := fuzz.NewConsumer(data)
	constraintStr, err := f.GetString()
	if err != nil {
		return 0
	}
	semverConstraint, err := semver.NewConstraint(constraintStr)
	if err != nil {
		return 0
	}
	mdMap := make(map[string]string)
	err = f.FuzzMap(&mdMap)
	if err != nil {
		return 0
	}
	md := metadata.New(mdMap)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_ = userAgentEnforcer(ctx, clientName, constraintStr, semverConstraint)
	return 1
}
