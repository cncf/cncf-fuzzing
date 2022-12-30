package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// importPathShort is a map to convert import paths to import aliases
var importPathShort = map[string]string{
	"go.etcd.io/etcd/server/v3/storage/wal/walpb":                      "walpb",
	"go.etcd.io/etcd/server/v3/etcdserver/api/v3election/v3electionpb": "v3electionpb",
	"go.etcd.io/etcd/server/v3/etcdserver/api/v3lock/v3lockpb":         "v3lockpb",
	"go.etcd.io/etcd/server/v3/etcdserver/api/snap/snappb":             "snappb",
	"go.etcd.io/etcd/server/v3/lease/leasepb":                          "leasepb",
	"go.etcd.io/etcd/tests/v3/functional/rpcpb":                        "rpcpb",
	"go.etcd.io/etcd/api/v3/authpb":                                    "authpb",
	"go.etcd.io/etcd/api/v3/mvccpb":                                    "mvccpb",
	"go.etcd.io/etcd/api/v3/membershippb":                              "membershippb",
	"go.etcd.io/etcd/api/v3/etcdserverpb":                              "etcdserverpb",
}

// pathToImportPath is a map to convert filepaths to import paths.
// the filepaths are available in the grep results.
var pathToImportPath = map[string]string{
	"./server/storage/wal/walpb/record.pb.go":                          "go.etcd.io/etcd/server/v3/storage/wal/walpb",
	"./server/etcdserver/api/v3election/v3electionpb/v3election.pb.go": "go.etcd.io/etcd/server/v3/etcdserver/api/v3election/v3electionpb",
	"./server/etcdserver/api/v3lock/v3lockpb/v3lock.pb.go":             "go.etcd.io/etcd/server/v3/etcdserver/api/v3lock/v3lockpb",
	"./server/etcdserver/api/snap/snappb/snap.pb.go":                   "go.etcd.io/etcd/server/v3/etcdserver/api/snap/snappb",
	"./server/lease/leasepb/lease.pb.go":                               "go.etcd.io/etcd/server/v3/lease/leasepb",
	"./tests/functional/rpcpb/rpc.pb.go":                               "go.etcd.io/etcd/tests/v3/functional/rpcpb",
	"./api/authpb/auth.pb.go":                                          "go.etcd.io/etcd/api/v3/authpb",
	"./api/mvccpb/kv.pb.go":                                            "go.etcd.io/etcd/api/v3/mvccpb",
	"./api/membershippb/membership.pb.go":                              "go.etcd.io/etcd/api/v3/membershippb",
	"./api/etcdserverpb/raft_internal.pb.go":                           "go.etcd.io/etcd/api/v3/etcdserverpb",
	"./api/etcdserverpb/rpc.pb.go":                                     "go.etcd.io/etcd/api/v3/etcdserverpb",
	"./api/etcdserverpb/etcdserver.pb.go":                              "go.etcd.io/etcd/api/v3/etcdserverpb",
}

// contains checks if a string is present in a string slice
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

/*
createFunctionCall creates a function call
This is used to create the calls to the internal harnesses:
switch funcOp {
case 0:

	_ = FuzzetcdserverpbRequest(data2)

case 1:

	_ = FuzzetcdserverpbMetadata(data2)

case 2:

	        _ = FuzzetcdserverpbResponseHeader(data2)
	}
*/
func createFunctionCall(shortName, structName string) string {
	return fmt.Sprintf("\t_ = Fuzz%s%s(data2)\n", shortName, structName)
}

/*
createHarness creates an internal harness.
An example of a generated harness:

	func FuzzetcdserverpbDeleteRangeResponse(data []byte) error {
	        f := fuzz.NewConsumer(data)
	        s := &etcdserverpb.DeleteRangeResponse{}
	        err := f.GenerateStruct(s)
	        if err != nil {
	                return err
	        }
	        b, err := s.Marshal()
	        if err != nil {
	                return err
	        }
	        s2 := &etcdserverpb.DeleteRangeResponse{}
	        err = s2.Unmarshal(b)
	        if err != nil {
	                return err
	        }
	        newBytes, err := f.GetBytes()
	        if err != nil {
	                return err
	        }
	        s3 := &etcdserverpb.DeleteRangeResponse{}
	        err = s3.Unmarshal(newBytes)
	        return err
	}
*/
func createHarness(shortName, structName string) string {
	var harnessString strings.Builder
	harnessString.WriteString(fmt.Sprintf("\n\nfunc Fuzz%s%s(data []byte) error {\n", shortName, structName))
	harnessString.WriteString("\tf := fuzz.NewConsumer(data)\n")
	harnessString.WriteString(fmt.Sprintf("\ts := &%s.%s{}\n", shortName, structName))
	harnessString.WriteString("\terr := f.GenerateStruct(s)\n")
	harnessString.WriteString("\tif err != nil {\n")
	harnessString.WriteString("\t\treturn err\n")
	harnessString.WriteString("\t}\n")
	harnessString.WriteString("\tb, err := s.Marshal()\n")
	harnessString.WriteString("\tif err != nil {\n")
	harnessString.WriteString("\t\treturn err\n")
	harnessString.WriteString("\t}\n")
	harnessString.WriteString(fmt.Sprintf("\ts2 := &%s.%s{}\n", shortName, structName))
	harnessString.WriteString("\terr = s2.Unmarshal(b)\n")
	harnessString.WriteString("\tif err != nil {\n")
	harnessString.WriteString("\t\treturn err\n")
	harnessString.WriteString("\t}\n")
	harnessString.WriteString("\tnewBytes, err := f.GetBytes()\n")
	harnessString.WriteString("\tif err != nil {\n")
	harnessString.WriteString("\t\treturn err\n")
	harnessString.WriteString("\t}\n")
	harnessString.WriteString(fmt.Sprintf("\ts3 := &%s.%s{}\n", shortName, structName))
	harnessString.WriteString("\terr = s3.Unmarshal(newBytes)\n")
	harnessString.WriteString("\treturn err\n")
	harnessString.WriteString("}\n")
	return harnessString.String()
}

// createMainFuzzer creates a file and writes all
// the accumulated sub-elements (imports, main harness,
// internal harnesses) of the fuzzer to it.
func createMainFuzzer(functionList, harnesses []string) {
	var mainFuzzer strings.Builder

	// package and imports
	mainFuzzer.WriteString("package fuzzing\n\n")
	mainFuzzer.WriteString("import (\n")
	for k, v := range importPathShort {
		mainFuzzer.WriteString(fmt.Sprintf("\t%s \"%s\"\n", v, k))
	}
	mainFuzzer.WriteString("\tfuzz \"github.com/AdaLogics/go-fuzz-headers\"\n")
	mainFuzzer.WriteString(")\n\n")

	// main entrypoint of the fuzzer
	mainFuzzer.WriteString("func FuzzAPIMarshal(data []byte) int {\n")
	mainFuzzer.WriteString("\tif len(data)<10{ return 0 }\n")

	// calls to each internal harness
	maxOps := len(functionList)
	mainFuzzer.WriteString(fmt.Sprintf("\tfuncOp := int(data[0])%%%d\n", maxOps))
	mainFuzzer.WriteString("\tdata2 := data[1:]\n")
	mainFuzzer.WriteString("\tswitch funcOp {\n")
	for i := 0; i < len(functionList); i++ {
		mainFuzzer.WriteString(fmt.Sprintf("\tcase %d:\n", i))
		mainFuzzer.WriteString(fmt.Sprintf("\t%s\n", functionList[i]))
	}
	mainFuzzer.WriteString("\t}\n")
	mainFuzzer.WriteString("\treturn 1\n")
	mainFuzzer.WriteString("}")

	// add all the internal harnesses
	for i := 0; i < len(harnesses); i++ {
		mainFuzzer.WriteString(harnesses[i])
	}

	// write the file
	fuzzFile, err := os.Create("api_marshal_fuzzer.go")
	if err != nil {
		panic(err)
	}
	defer fuzzFile.Close()
	fuzzFile.WriteString(mainFuzzer.String())
}

// getGrepData extracts the required data from the grep result
func getGrepData() ([]string, []string) {
	// paths contains all import paths
	paths := make([]string, 0)

	// functionList contains the calls to all the harnesses
	functionList := make([]string, 0)

	// harnesses contains all the harnesses
	harnesses := make([]string, 0)

	// extract data from the grep results:
	f, _ := os.Open("/tmp/marshal_targets.txt")
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "func (") {
			thePath := strings.Split(line, ":")[0]
			if _, ok := pathToImportPath[thePath]; !ok {
				continue
			}
			if !contains(paths, thePath) {
				paths = append(paths, thePath)
			}
			targetStructTemp := strings.Split(line, "func (m *")
			if len(targetStructTemp) == 1 {
				continue
			}

			// get name of target struct
			structName := strings.Split(targetStructTemp[1], ") ")[0]

			// get import path and short name
			importPath := pathToImportPath[thePath]
			shortName := importPathShort[importPath]
			//fmt.Println(createHarness(shortName, structName))

			// create harness
			harness := createHarness(shortName, structName)
			harnesses = append(harnesses, harness)

			// add harness to list of function calls
			functionList = append(functionList, createFunctionCall(shortName, structName))
		}
	}
	return functionList, harnesses
}

func main() {
	functionList, harnesses := getGrepData()
	createMainFuzzer(functionList, harnesses)
}
