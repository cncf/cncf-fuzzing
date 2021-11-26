# Copyright 2021 ADA Logics LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from argparse import ArgumentParser

# In the same dir as this file we need a
# file called "input_file" that has the
# result of this command: grep -r ") Marshal()" . > input_file

# internal_target_list is a list of just the function identifiers
# of the internal targets. This is used when creating the calls
# to the internal targets in the main fuzzer.
internal_target_list = []

# Takes a string like this:
# ./staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1/generated.pb.go:func (m *ExternalDocumentation) Marshal() (dAtA []byte, err error) {
# and should return a string like this:
# k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1
def get_import_path(line):
	import_path = line.split(":")[0].split("./staging/src/")[-1].rsplit("/", 1)[0]
	return import_path



# This takes:
# a struct name which could be this: CustomResourceDefinitionVersion
# an import path which could be this: k8s.io/api/storage/v1beta1
# And returns a string like this: Fuzzstoragev1beta1CustomResourceDefinitionVersion
def create_fuzzer_name(struct_name, import_path):
	split_import_path = import_path.split("/")
	second_last = split_import_path[-2]
	last = split_import_path[-1]

	fuzz_name = "Fuzz"
	fuzz_name += "%s%s%s"%(second_last, last, struct_name)
	return fuzz_name


# This takes:
# an import path which could be this: k8s.io/api/storage/v1beta1
# And returns a unique ID for this import like this: storagev1beta
def create_import_id(import_path):
	split_import_path = import_path.split("/")
	second_last = split_import_path[-2]
	last = split_import_path[-1]
	return "%s%s"%(second_last, last)


# protobuf test below is from: https://github.com/kubernetes/kubernetes/blob/a5489431cfc0598dad421fccd2d713f84bf520bd/pkg/api/testing/serialization_proto_test.go#L100
# Creates an internal target.
# This is an unexported function that the fuzz harness will call
# Example:
# func fuzzdiscoveryv1beta1EndpointHints(data []byte) {
#	m1 := &discoveryv1beta1.EndpointHints{}
#	data2 := data
#	err := m1.Unmarshal(data)
#	if err != nil {
#		return
#	}
#	correctData1, err := m1.Marshal()
#	if err != nil {
#		panic(err)
#	}
#	m2 := &discoveryv1beta1.EndpointHints{}
#	err = m2.Unmarshal(data2)
#	if err != nil {
#		panic(err)
#	}
#	correctData2, err := m2.Marshal()
#	if err != nil {
#		panic(err)
#	}
#	if !reflect.DeepEqual(m1, m2) {
#		fmt.Printf("%+v\n", m1)
#		fmt.Printf("%+v\n", m2)
#		panic("done")
#	}
#	checkData(correctData1, correctData2)
# }
def create_internal_target(import_id, struct_name):
	func_name = "fuzz%s%s"%(import_id, struct_name)
	fuzzer_template1 = ""
	fuzzer_template1 += "func %s(data []byte) {\n"%(func_name)
	fuzzer_template1 += "\tm1 := &%s.%s{}"%(import_id, struct_name)
	fuzzer_template1 += """
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	"""
	fuzzer_template1 += "m2 := &%s.%s{}\n"%(import_id, struct_name)
	fuzzer_template1 += """\terr = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\\n", m1)
		fmt.Printf("%+v\\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}
"""
	internal_target_list.append(func_name)
	return fuzzer_template1

# This creates the part of the main harness that determines
# which marshaling function should be called.
def create_fuzzer_branches():
	i = 0
	body = ""
	for target in internal_target_list:
		if i==0:
			body += "\tif op%%noOfTargets==%s {\n"%(i)
			body +="\t\t%s(inputData)\n"%(target)
		else:
			body += "\t} else if op%%noOfTargets==%s {\n"%(i)
			body +="\t\t%s(inputData)\n"%(target)
		i+=1
	body += "\t}\n"
	return body

def get_check_data_func():
	return """func checkData(correctData1, correctData2 []byte) {
	if len(correctData1)!=len(correctData2) {
		panic("Len should be equal.")
	}
}\n\n"""

# create_fuzz_harness creates the complete file including:
# - package
# - imports
# - main fuzz harness
# - all internal functions called by the main harness
def create_fuzz_harness(import_string, internal_targets):
	fuzz_harness = ""

	# package
	fuzz_harness += "package fuzzing\n"
	
	# imports
	fuzz_harness += "import (\n"
	fuzz_harness += "\t\"fmt\"\n"
	fuzz_harness += "\t\"reflect\"\n"
	fuzz_harness += import_string
	fuzz_harness += "\n)\n"

	fuzz_harness += "\nconst noOfTargets = %s\n\n"%(len(internal_target_list))

	fuzz_harness += get_check_data_func()

	# Fuzzer
	fuzz_harness += "func FuzzApiMarshaling(data []byte) int {\n"
	fuzz_harness += "\tif len(data)<10 {\n"
	fuzz_harness += "\t\treturn 0\n"
	fuzz_harness += "\t}\n"
	fuzz_harness += "\top := int(data[0])\n"
	fuzz_harness += "\tinputData := data[1:]\n"
	fuzz_harness += "\t"+create_fuzzer_branches()+"\n"
	fuzz_harness += "\treturn 1\n"
	fuzz_harness += "}\n"

	fuzz_harness += internal_targets

	return fuzz_harness

# creates all the data needed to create the complete file, including:
def create_data(input_file):

	# import_string is a string that we append all imports to
	import_string = ""

	# internal_targets is a string that we append all internal
	# function to.
	internal_targets = ""

	# import_list holds all the imported modules
	# Every time a module is imported by the fuzzer, we check if 
	# it exists in import_list. If not, then we can import it,
	# and we add it to import_list.
	# The ultimate purpose of this is to avoid duplicate imports.
	import_list = []

	with open(input_file, "r") as f:
		lines = f.readlines()
		for line in lines:
			line = line.rstrip()

			# Ignore vendor
			if "/vendor/" in line:
				continue

			# All autogenerated apis have these return values:
			if "dAtA []byte, err error" not in line:
				continue

			# For now I am removing all examples.
			# This may remove stuff that we want to fuzz
			# but it is easy for now.
			if "example" in line:
				continue
			
			# For now we only support pointers to structs.
			# Todo: fix this
			if "func (m *" not in line:
				continue

			# Import related
			import_path = get_import_path(line)
			import_id = create_import_id(import_path)
			if import_path not in import_list:
				import_list.append(import_path)
				import_string += "\t%s \"%s\"\n"%(import_id, import_path)

			func = line.split(":")[-1].split("func (m *")[-1]
			struct_name = func.split(")", 1)[0]

			fuzz_name = create_fuzzer_name(struct_name, import_path)
			internal_targets += "\n"+create_internal_target(import_id, struct_name)+"\n"

	return import_string, internal_targets

def main():
	parser = ArgumentParser()
	parser.add_argument("-f", "--input_file", dest="input_file",
                    help="write report to FILE", metavar="FILE")
	args = parser.parse_args()
	print(args.input_file)
	import_string, internal_targets = create_data(args.input_file)
	with open("api_marshaling_fuzzer.go", "w") as f:
		f.write(create_fuzz_harness(import_string, internal_targets))

if __name__ == "__main__":
    main()