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

// Package fzconsumer provides a fuzz data consumer for structured fuzzing.
//
// It is a drop-in replacement for github.com/AdaLogics/go-fuzz-headers with
// these improvements:
//
//   - GetInt() reads 4 bytes (full uint32 range) instead of 1 byte (0-255).
//   - GetString() returns "" on error instead of the literal string "nil".
//   - GetUint16/GetUint64 do not waste a byte on an endianness coin flip.
//   - GetBytes() uses a 2-byte length header instead of 4 bytes.
//   - New methods: GetIntRange, GetOneOf, RemainingBytes.
//   - Richer SQL generation with Vitess-specific statements.
package gofuzzheaders

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"unsafe"
)

// ErrNotEnoughData is returned when the fuzz input has been exhausted.
var ErrNotEnoughData = errors.New("not enough data")

const maxDepth = 100

// IsDivisibleBy is a utility function kept for backward compatibility.
func IsDivisibleBy(n, divisibleBy int) bool {
	return (n % divisibleBy) == 0
}

// Continue is passed to custom type-generation functions registered via Funcs.
type Continue struct {
	F *ConsumeFuzzer
}

// ConsumeFuzzer reads structured typed values out of raw fuzz bytes.
type ConsumeFuzzer struct {
	data      []byte
	dataTotal uint32
	position  uint32

	// Public fields used by Split().
	CommandPart   []byte
	RestOfArray   []byte
	NumberOfCalls int

	// Configuration.
	fuzzUnexportedFields bool
	forceUTF8Strings     bool

	// Struct generation.
	curDepth int
	Funcs    map[reflect.Type]reflect.Value
}

// NewConsumer creates a ConsumeFuzzer backed by the given fuzz data.
func NewConsumer(data []byte) *ConsumeFuzzer {
	return &ConsumeFuzzer{
		data:      data,
		dataTotal: uint32(len(data)),
		Funcs:     make(map[reflect.Type]reflect.Value),
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// AllowUnexportedFields enables fuzzing of unexported struct fields.
func (f *ConsumeFuzzer) AllowUnexportedFields() { f.fuzzUnexportedFields = true }

// DisallowUnexportedFields disables fuzzing of unexported struct fields (default).
func (f *ConsumeFuzzer) DisallowUnexportedFields() { f.fuzzUnexportedFields = false }

// AllowNonUTF8Strings allows generated strings to contain arbitrary bytes.
func (f *ConsumeFuzzer) AllowNonUTF8Strings() { f.forceUTF8Strings = false }

// DisallowNonUTF8Strings forces generated strings to be valid UTF-8.
func (f *ConsumeFuzzer) DisallowNonUTF8Strings() { f.forceUTF8Strings = true }

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// RemainingBytes returns how many unconsumed bytes remain.
func (f *ConsumeFuzzer) RemainingBytes() int {
	if f.position >= f.dataTotal {
		return 0
	}
	return int(f.dataTotal - f.position)
}

// ---------------------------------------------------------------------------
// Primitive getters
// ---------------------------------------------------------------------------

// GetByte consumes 1 byte.
func (f *ConsumeFuzzer) GetByte() (byte, error) {
	if f.position >= f.dataTotal {
		return 0, ErrNotEnoughData
	}
	b := f.data[f.position]
	f.position++
	return b, nil
}

// GetBool consumes 1 byte and returns true if the low bit is set.
func (f *ConsumeFuzzer) GetBool() (bool, error) {
	b, err := f.GetByte()
	if err != nil {
		return false, err
	}
	return b&1 == 1, nil
}

// GetInt consumes 4 bytes and returns a non-negative int.
// This is a major improvement over go-fuzz-headers which reads only 1 byte
// (0-255). Four bytes give a range of 0 to 4,294,967,295 which makes
// modulo-based selection (val % N) produce much better coverage.
func (f *ConsumeFuzzer) GetInt() (int, error) {
	if f.position+4 > f.dataTotal {
		// Graceful fallback: use whatever bytes remain.
		if f.position >= f.dataTotal {
			return 0, ErrNotEnoughData
		}
		var val int
		for f.position < f.dataTotal {
			val = (val << 8) | int(f.data[f.position])
			f.position++
		}
		return val, nil
	}
	val := binary.LittleEndian.Uint32(f.data[f.position : f.position+4])
	f.position += 4
	return int(val), nil
}

// GetIntRange consumes the minimum bytes needed and returns a value in [min, max].
func (f *ConsumeFuzzer) GetIntRange(min, max int) (int, error) {
	if min > max {
		return 0, fmt.Errorf("GetIntRange: min (%d) > max (%d)", min, max)
	}
	if min == max {
		return min, nil
	}
	span := max - min + 1
	if span <= 256 {
		b, err := f.GetByte()
		if err != nil {
			return 0, err
		}
		return min + int(b)%span, nil
	}
	if span <= 65536 {
		v, err := f.GetUint16()
		if err != nil {
			return 0, err
		}
		return min + int(v)%span, nil
	}
	v, err := f.GetInt()
	if err != nil {
		return 0, err
	}
	if v < 0 {
		v = -v
	}
	return min + v%span, nil
}

// GetUint16 consumes 2 bytes (little-endian).
// Unlike go-fuzz-headers this does NOT waste an extra byte on an endianness
// coin flip.
func (f *ConsumeFuzzer) GetUint16() (uint16, error) {
	if f.position+2 > f.dataTotal {
		return 0, ErrNotEnoughData
	}
	val := binary.LittleEndian.Uint16(f.data[f.position : f.position+2])
	f.position += 2
	return val, nil
}

// GetUint32 consumes 4 bytes (little-endian).
func (f *ConsumeFuzzer) GetUint32() (uint32, error) {
	if f.position+4 > f.dataTotal {
		return 0, ErrNotEnoughData
	}
	val := binary.LittleEndian.Uint32(f.data[f.position : f.position+4])
	f.position += 4
	return val, nil
}

// GetUint64 consumes 8 bytes (little-endian).
// Unlike go-fuzz-headers this does NOT waste an extra byte on an endianness
// coin flip.
func (f *ConsumeFuzzer) GetUint64() (uint64, error) {
	if f.position+8 > f.dataTotal {
		return 0, ErrNotEnoughData
	}
	val := binary.LittleEndian.Uint64(f.data[f.position : f.position+8])
	f.position += 8
	return val, nil
}

// GetUint consumes 4 or 8 bytes depending on platform word size.
func (f *ConsumeFuzzer) GetUint() (uint, error) {
	var zero uint
	if unsafe.Sizeof(zero) == 8 {
		v, err := f.GetUint64()
		return uint(v), err
	}
	v, err := f.GetUint32()
	return uint(v), err
}

// GetFloat32 consumes 4 bytes.
func (f *ConsumeFuzzer) GetFloat32() (float32, error) {
	bits, err := f.GetUint32()
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(bits), nil
}

// GetFloat64 consumes 8 bytes.
func (f *ConsumeFuzzer) GetFloat64() (float64, error) {
	bits, err := f.GetUint64()
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(bits), nil
}

// ---------------------------------------------------------------------------
// Bytes / Strings
// ---------------------------------------------------------------------------

// GetNBytes consumes exactly n bytes.
func (f *ConsumeFuzzer) GetNBytes(n int) ([]byte, error) {
	if int(f.dataTotal-f.position) < n {
		return nil, ErrNotEnoughData
	}
	out := make([]byte, n)
	copy(out, f.data[f.position:f.position+uint32(n)])
	f.position += uint32(n)
	return out, nil
}

// GetBytes consumes a 2-byte length prefix then that many bytes.
// The length is capped at the remaining data. Unlike go-fuzz-headers which
// uses a 4-byte length prefix, this saves 2 bytes per call.
func (f *ConsumeFuzzer) GetBytes() ([]byte, error) {
	raw, err := f.GetUint16()
	if err != nil {
		return nil, ErrNotEnoughData
	}
	length := int(raw)
	remaining := int(f.dataTotal - f.position)
	if remaining <= 0 {
		return nil, ErrNotEnoughData
	}
	if length > remaining {
		length = remaining
	}
	out := make([]byte, length)
	copy(out, f.data[f.position:f.position+uint32(length)])
	f.position += uint32(length)
	return out, nil
}

// GetString consumes a 2-byte length prefix then that many bytes as a string.
// On error it returns "" (go-fuzz-headers returns the literal "nil" which is
// a bug that has caused real confusion in fuzzers).
func (f *ConsumeFuzzer) GetString() (string, error) {
	raw, err := f.GetUint16()
	if err != nil {
		return "", err
	}
	length := int(raw)
	remaining := int(f.dataTotal - f.position)
	if remaining <= 0 {
		return "", ErrNotEnoughData
	}
	if length > remaining {
		length = remaining
	}
	begin := f.position
	f.position += uint32(length)
	s := string(f.data[begin:f.position])
	if f.forceUTF8Strings {
		s = strings.ToValidUTF8(s, "")
	}
	return s, nil
}

// GetStringFrom returns a string of the given length using only characters
// from possibleChars.
func (f *ConsumeFuzzer) GetStringFrom(possibleChars string, length int) (string, error) {
	if len(possibleChars) == 0 {
		return "", fmt.Errorf("empty character set")
	}
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		b, err := f.GetByte()
		if err != nil {
			return string(out[:i]), err
		}
		out[i] = possibleChars[int(b)%len(possibleChars)]
	}
	return string(out), nil
}

// GetRune returns a slice of runes derived from a fuzz string.
func (f *ConsumeFuzzer) GetRune() ([]rune, error) {
	s, err := f.GetString()
	if err != nil {
		return nil, err
	}
	return []rune(s), nil
}

// GetStringArray returns a reflect.Value containing a []string.
func (f *ConsumeFuzzer) GetStringArray() (reflect.Value, error) {
	b, err := f.GetByte()
	if err != nil {
		return reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf("")), 0, 0), err
	}
	n := int(b) % 20
	arr := reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf("")), 0, n)
	for i := 0; i < n; i++ {
		s, err := f.GetString()
		if err != nil {
			break
		}
		arr = reflect.Append(arr, reflect.ValueOf(s))
	}
	return arr, nil
}

// GetOneOf picks one element from options using a single byte.
func (f *ConsumeFuzzer) GetOneOf(options []string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("empty options list")
	}
	b, err := f.GetByte()
	if err != nil {
		return "", err
	}
	return options[int(b)%len(options)], nil
}

// ---------------------------------------------------------------------------
// Split
// ---------------------------------------------------------------------------

// Split divides the fuzz data into a command part and a rest-of-array part.
// This is kept for backward compatibility with fuzzers that use it.
func (f *ConsumeFuzzer) Split(minCalls, maxCalls int) error {
	if f.dataTotal == 0 {
		return errors.New("could not split: empty data")
	}
	numberOfCalls := int(f.data[0])
	if numberOfCalls < minCalls || numberOfCalls > maxCalls {
		return fmt.Errorf("bad number of calls: %d not in [%d, %d]", numberOfCalls, minCalls, maxCalls)
	}
	if int(f.dataTotal) < numberOfCalls+numberOfCalls+1 {
		return errors.New("data too short for requested split")
	}
	commandPart := f.data[1 : numberOfCalls+1]
	restOfArray := f.data[numberOfCalls+1:]
	if len(commandPart) != numberOfCalls {
		return errors.New("internal split error")
	}
	if !IsDivisibleBy(len(restOfArray), numberOfCalls) {
		return errors.New("rest of array not divisible by number of calls")
	}
	f.CommandPart = commandPart
	f.RestOfArray = restOfArray
	f.NumberOfCalls = numberOfCalls
	return nil
}

// ---------------------------------------------------------------------------
// Struct / Slice / Map generation
// ---------------------------------------------------------------------------

// GenerateStruct fills targetStruct (must be a pointer) with fuzzed values.
func (f *ConsumeFuzzer) GenerateStruct(targetStruct interface{}) error {
	e := reflect.ValueOf(targetStruct).Elem()
	return f.fuzzStruct(e, false)
}

// CreateSlice is an alias for GenerateStruct that communicates intent.
func (f *ConsumeFuzzer) CreateSlice(targetSlice interface{}) error {
	return f.GenerateStruct(targetSlice)
}

// FuzzMap is an alias for GenerateStruct that communicates intent.
func (f *ConsumeFuzzer) FuzzMap(m interface{}) error {
	return f.GenerateStruct(m)
}

func (f *ConsumeFuzzer) setCustom(v reflect.Value) error {
	doCustom, ok := f.Funcs[v.Type()]
	if !ok {
		return fmt.Errorf("no custom function for type %v", v.Type())
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("cannot set nil pointer for custom function")
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
	case reflect.Map:
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("cannot set nil map for custom function")
			}
			v.Set(reflect.MakeMap(v.Type()))
		}
	default:
		return fmt.Errorf("custom functions only supported for pointer and map types")
	}
	result := doCustom.Call([]reflect.Value{v, reflect.ValueOf(Continue{F: f})})
	if result[0].IsNil() {
		return nil
	}
	return fmt.Errorf("custom function returned error")
}

func (f *ConsumeFuzzer) fuzzStruct(e reflect.Value, customFunctions bool) error {
	if f.curDepth >= maxDepth {
		return nil
	}
	f.curDepth++
	defer func() { f.curDepth-- }()

	if customFunctions && e.IsValid() && e.CanAddr() {
		err := f.setCustom(e.Addr())
		if err == nil {
			return nil
		}
	}

	switch e.Kind() {
	case reflect.Struct:
		for i := 0; i < e.NumField(); i++ {
			field := e.Field(i)
			if !field.CanSet() {
				if f.fuzzUnexportedFields {
					field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
				} else {
					continue
				}
			}
			if err := f.fuzzStruct(field, customFunctions); err != nil {
				return err
			}
		}

	case reflect.String:
		str, err := f.GetString()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetString(str)
		}

	case reflect.Slice:
		var maxElements uint32 = 50
		if e.Type().Elem().Kind() == reflect.Uint8 {
			maxElements = 10000
		}
		randQty, err := f.GetUint32()
		if err != nil {
			return err
		}
		numOfElements := randQty % maxElements
		remaining := f.dataTotal - f.position
		if numOfElements > remaining {
			numOfElements = remaining
		}
		sl := reflect.MakeSlice(e.Type(), int(numOfElements), int(numOfElements))
		for i := 0; i < int(numOfElements); i++ {
			if err := f.fuzzStruct(sl.Index(i), customFunctions); err != nil {
				if i >= 10 {
					if e.CanSet() {
						e.Set(sl.Slice(0, i))
					}
					return nil
				}
				return err
			}
		}
		if e.CanSet() {
			e.Set(sl)
		}

	case reflect.Uint:
		v, err := f.GetUint()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(v))
		}

	case reflect.Uint8:
		b, err := f.GetByte()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(b))
		}

	case reflect.Uint16:
		v, err := f.GetUint16()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(v))
		}

	case reflect.Uint32:
		v, err := f.GetUint32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(v))
		}

	case reflect.Uint64:
		v, err := f.GetUint64()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(v)
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := f.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetInt(int64(v))
		}

	case reflect.Float32:
		v, err := f.GetFloat32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(v))
		}

	case reflect.Float64:
		v, err := f.GetFloat64()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(v)
		}

	case reflect.Bool:
		b, err := f.GetBool()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetBool(b)
		}

	case reflect.Map:
		if e.CanSet() {
			e.Set(reflect.MakeMap(e.Type()))
			randQty, err := f.GetByte()
			if err != nil {
				return err
			}
			numOfElements := int(randQty) % 50
			for i := 0; i < numOfElements; i++ {
				key := reflect.New(e.Type().Key()).Elem()
				if err := f.fuzzStruct(key, customFunctions); err != nil {
					return err
				}
				val := reflect.New(e.Type().Elem()).Elem()
				if err := f.fuzzStruct(val, customFunctions); err != nil {
					return err
				}
				e.SetMapIndex(key, val)
			}
		}

	case reflect.Ptr:
		if e.CanSet() {
			e.Set(reflect.New(e.Type().Elem()))
			if err := f.fuzzStruct(e.Elem(), customFunctions); err != nil {
				return err
			}
		}
	}

	return nil
}
