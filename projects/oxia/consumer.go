// Copyright 2026 the cncf-fuzzing authors
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
///////////////////////////////////////////////////////////////////////////

package fuzz

// fuzzConsumer extracts typed values from raw fuzz input bytes,
// similar to libFuzzer's FuzzedDataProvider. This allows fuzzers to accept a
// single []byte input while consuming multiple typed values.
type fuzzConsumer struct {
	data []byte
	pos  int
}

func newConsumer(data []byte) *fuzzConsumer {
	return &fuzzConsumer{data: data}
}

func (c *fuzzConsumer) remaining() int {
	return len(c.data) - c.pos
}

func (c *fuzzConsumer) consumeByte() (byte, bool) {
	if c.pos >= len(c.data) {
		return 0, false
	}
	b := c.data[c.pos]
	c.pos++
	return b, true
}

func (c *fuzzConsumer) consumeN(n int) ([]byte, bool) {
	if c.remaining() < n {
		return nil, false
	}
	b := make([]byte, n)
	copy(b, c.data[c.pos:c.pos+n])
	c.pos += n
	return b, true
}

// consumeString reads a length-prefixed string. The first byte is the length
// (capped at maxLen and remaining data), followed by that many bytes.
func (c *fuzzConsumer) consumeString(maxLen int) (string, bool) {
	lenByte, ok := c.consumeByte()
	if !ok {
		return "", false
	}
	strLen := int(lenByte)
	if strLen > maxLen {
		strLen = maxLen
	}
	if strLen > c.remaining() {
		strLen = c.remaining()
	}
	s := string(c.data[c.pos : c.pos+strLen])
	c.pos += strLen
	return s, true
}

// consumeBytes reads a length-prefixed byte slice.
func (c *fuzzConsumer) consumeBytes(maxLen int) ([]byte, bool) {
	lenByte, ok := c.consumeByte()
	if !ok {
		return nil, false
	}
	bLen := int(lenByte)
	if bLen > maxLen {
		bLen = maxLen
	}
	if bLen > c.remaining() {
		bLen = c.remaining()
	}
	result := make([]byte, bLen)
	copy(result, c.data[c.pos:c.pos+bLen])
	c.pos += bLen
	return result, true
}

func (c *fuzzConsumer) consumeBool() (bool, bool) {
	b, ok := c.consumeByte()
	return b%2 == 1, ok
}

func (c *fuzzConsumer) consumeUint8() (uint8, bool) {
	return c.consumeByte()
}

func (c *fuzzConsumer) consumeUint16() (uint16, bool) {
	b, ok := c.consumeN(2)
	if !ok {
		return 0, false
	}
	return uint16(b[0])<<8 | uint16(b[1]), true
}

func (c *fuzzConsumer) consumeInt32() (int32, bool) {
	b, ok := c.consumeN(4)
	if !ok {
		return 0, false
	}
	return int32(b[0])<<24 | int32(b[1])<<16 | int32(b[2])<<8 | int32(b[3]), true
}

func (c *fuzzConsumer) consumeInt64() (int64, bool) {
	b, ok := c.consumeN(8)
	if !ok {
		return 0, false
	}
	return int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7]), true
}

// consumeRest returns all remaining bytes.
func (c *fuzzConsumer) consumeRest() []byte {
	if c.pos >= len(c.data) {
		return nil
	}
	rest := make([]byte, len(c.data)-c.pos)
	copy(rest, c.data[c.pos:])
	c.pos = len(c.data)
	return rest
}

// Seed encoding helpers for constructing f.Add() seed data.

func encStr(s string) []byte {
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func encBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

func encUint16(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

func encInt32(v int32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func encInt64(v int64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

func buildSeed(parts ...[]byte) []byte {
	var result []byte
	for _, p := range parts {
		result = append(result, p...)
	}
	return result
}
