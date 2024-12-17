package containerstoragemock

import (
	"fmt"
	istorage "github.com/containers/image/v5/storage"
	"go.uber.org/mock/gomock"
	"runtime"
	"strings"
)

var (
	mockCtrl *gomock.Controller
)

func init() {

	t := &FuzzTester{}
	mockCtrl = gomock.NewController(t)
}
func FuzzParseStoreReference(data []byte) int {
	defer catchPanics()
	if len(string(data)) <= 3 && strings.ContainsAny(string(data), "@:") {
		return 0
	}
	t := &FuzzTester{}
	mockCtrl = gomock.NewController(t)
	storeMock := NewMockStore(mockCtrl)
	_ = mockParseStoreReference(storeMock, string(data))
	_, _ = istorage.Transport.ParseStoreReference(storeMock, string(data))
	return 1
}

func catchPanics() {
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
		if strings.Contains(err, "Fatal panic from fuzzer") {
			return
		} else {
			panic(err)
		}
	}
}

type FuzzTester struct {
}

func (ft *FuzzTester) Cleanup(func())                            {}
func (ft *FuzzTester) Setenv(kev, value string)                  {}
func (ft *FuzzTester) Error(args ...interface{})                 {}
func (ft *FuzzTester) Errorf(format string, args ...interface{}) {}
func (ft *FuzzTester) Fail()                                     {}
func (ft *FuzzTester) FailNow()                                  {}
func (ft *FuzzTester) Failed() bool                              { return true }
func (ft *FuzzTester) Fatal(args ...interface{})                 { panic("Fatal panic from fuzzer") }
func (ft *FuzzTester) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf("Fatal panic from fuzzer"))
}
func (ft *FuzzTester) Helper()                                  {}
func (ft *FuzzTester) Log(args ...interface{})                  {}
func (ft *FuzzTester) Logf(format string, args ...interface{})  {}
func (ft *FuzzTester) Name() string                             { return "fuzz" }
func (ft *FuzzTester) Parallel()                                {}
func (ft *FuzzTester) Skip(args ...interface{})                 {}
func (ft *FuzzTester) SkipNow()                                 {}
func (ft *FuzzTester) Skipf(format string, args ...interface{}) {}
func (ft *FuzzTester) Skipped() bool                            { return true }
func (ft *FuzzTester) TempDir() string                          { return "/tmp" }
