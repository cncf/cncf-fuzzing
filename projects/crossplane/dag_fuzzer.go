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

package dag

import (
	"errors"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

type SimpleFuzzNode struct {
	IdentifierString string
	NeighborsField   map[string]SimpleFuzzNode
}

func toNodesFuzz(n []SimpleFuzzNode) []Node {
	nodes := make([]Node, len(n))
	for i, r := range n {
		r := r // Pin range variable so we can take its address.
		nodes[i] = &r
	}
	return nodes
}

func (s *SimpleFuzzNode) AddNeighbors(nodes ...Node) error {
	for _, n := range nodes {
		sn, ok := n.(*SimpleFuzzNode)
		if !ok {
			return errors.New("not a simple node")
		}
		s.NeighborsField[sn.Identifier()] = *sn
	}
	return nil
}

func (s *SimpleFuzzNode) Identifier() string {
	return s.IdentifierString
}

func (s *SimpleFuzzNode) Neighbors() []Node {
	nodes := make([]Node, len(s.NeighborsField))
	i := 0
	for _, r := range s.NeighborsField {
		r := r // Pin range variable so we can take its address.
		nodes[i] = &r
		i++
	}
	return nodes
}

func FuzzDag(data []byte) int {
	f := fuzz.NewConsumer(data)
	nodes := make([]SimpleFuzzNode, 0)
	err := f.CreateSlice(&nodes)
	if err != nil {
		return 0
	}
	d := NewMapDag()

	_, _ = d.Init(toNodesFuzz(nodes))
	return 1
}
