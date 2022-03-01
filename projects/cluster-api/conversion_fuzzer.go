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

package v1alpha3

import (
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/api/v1alpha4"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	utilconversion "sigs.k8s.io/cluster-api/util/conversion"
)

func createConditions() clusterv1.Conditions {
	return clusterv1.Conditions{}
}

func customMachineHealth() []interface{} {
	return []interface{}{
		func(mds *clusterv1.MachineDeploymentStatus, c fuzz.Continue) error {
			phase, err := c.F.GetString()
			if err != nil {
				return err
			}
			observedGeneration, err := c.F.GetInt()
			if err != nil {
				return err
			}
			selector, err := c.F.GetString()
			if err != nil {
				return err
			}
			replicas, err := c.F.GetInt()
			if err != nil {
				return err
			}
			updatedReplicas, err := c.F.GetInt()
			if err != nil {
				return err
			}
			mds.Phase = phase
			mds.Conditions = createConditions()
			mds.ObservedGeneration = int64(observedGeneration)
			mds.Selector = selector
			mds.Replicas = int32(replicas)
			mds.UpdatedReplicas = int32(updatedReplicas)
			//fmt.Printf("%+v\n", mds)
			return nil
		},
		func(mss *clusterv1.MachineSetStatus, c fuzz.Continue) error {
			err := c.GenerateStruct(mss)
			if err != nil {
				return err
			}
			mss.Conditions = createConditions()
			return nil
		},
		func(ms *clusterv1.MachineStatus, c fuzz.Continue) error {
			err := c.GenerateStruct(ms)
			if err != nil {
				return err
			}
			nsi := &corev1.NodeSystemInfo{}
			err = c.GenerateStruct(nsi)
			if err != nil {
				return err
			}
			nsi.BootID = "44a832f3-8cfb-4de5-b7d2-d66030b6cd95"
			nsi.OperatingSystem = "linux"
			nsi.KubeletVersion = "fuzzVersion"
			nsi.SystemUUID = "SystemUUID"
			nsi.KubeProxyVersion = "KubeProxyVersion"
			nsi.Architecture = "fuzz"
			nsi.MachineID = "fuzz"
			nsi.ContainerRuntimeVersion = "fuzz"
			/*nsi.KernelVersion = cadvisortest.FakeKernelVersion
			  nsi.OSImage = cadvisortest.FakeContainerOSVersion*/
			nsi.KernelVersion = "fuzz"
			nsi.OSImage = "fuzz"

			ms.NodeInfo = nsi
			ms.Conditions = createConditions()
			return nil
		},
		func(ms *v1alpha4.MachineStatus, c fuzz.Continue) error {
			err := c.GenerateStruct(ms)
			if err != nil {
				return err
			}
			ms.Version = nil
			return nil
		},
		func(ccs *clusterv1.ClusterClassSpec, c fuzz.Continue) error {
			err := c.GenerateStruct(ccs)
			if err != nil {
				return err
			}
			if len(ccs.Variables) == 0 {
				ccs.Variables = nil
			}
			if len(ccs.Patches) == 0 {
				ccs.Patches = nil
			}
			return nil
		},
		func(ccs *intstr.IntOrString, c fuzz.Continue) error {
			if ccs == nil {
				return fmt.Errorf("intstr was nil")
			}
			makeStr, err := c.F.GetBool()
			if err != nil {
				return err
			}
			if makeStr {
				ccs.Type = 1
				newStr, err := c.F.GetString()
				if err != nil {
					return err
				}
				ccs.StrVal = newStr
				ccs.IntVal = 0
			} else {
				ccs.Type = 2
				ccs.StrVal = ""
				newInt, err := c.F.GetInt()
				if err != nil {
					return err
				}
				ccs.IntVal = int32(newInt)
			}
			
			return nil
		},
		func(conds *clusterv1.Conditions, c fuzz.Continue) error {
			//Conditions need some modificatons, but setting them here
			// won't work, so we check in the fuzzer wheterh they are set properly.
			return nil
		},
		func(mrds *clusterv1.MachineRollingUpdateDeployment, c fuzz.Continue) error {
			err := c.GenerateStruct(mrds)
			if err != nil {
				return err
			}
			newString := "DeletePolicy"
			mrds.DeletePolicy = &newString
			return nil
		},
		func(met *metav1.TypeMeta, c fuzz.Continue) error {
			met.APIVersion = ""
			met.Kind = ""
			return nil
		},
		func(nsi *corev1.NodeSystemInfo, c fuzz.Continue) error {
			err := c.GenerateStruct(nsi)
			if err != nil {
				return err
			}
			validChars := "-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			bootid, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			operatingsystem, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			kubeletversion, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			systemuuid, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			kubeproxyversion, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			architecture, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			machineid, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			containerruntimeversion, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			kernelversion, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			osimage, err := c.F.GetStringFrom(validChars, 40)
			if err != nil {
				return err
			}
			nsi.BootID = bootid
			nsi.OperatingSystem = operatingsystem
			nsi.KubeletVersion = kubeletversion
			nsi.SystemUUID = systemuuid
			nsi.KubeProxyVersion = kubeproxyversion
			nsi.Architecture = architecture
			nsi.MachineID = machineid
			nsi.ContainerRuntimeVersion = containerruntimeversion
			nsi.KernelVersion = kernelversion
			nsi.OSImage = osimage
			return nil
		},
		func(top *clusterv1.Topology, c fuzz.Continue) error {
			layout := "Mon, 01/02/06, 03:04PM"
			timeStr := "Thu, 02/03/07, 04:05PM"
			rolloutAfter, err := time.Parse(layout, timeStr)
			if err != nil {
				return err
			}
			newTime := metav1.NewTime(rolloutAfter)
			top.RolloutAfter = &newTime
			return nil
		},
		func(mhs *clusterv1.MachineHealthCheckSpec, c fuzz.Continue) error {
			err := c.GenerateStruct(mhs)
			if err != nil {
				return err
			}
			unhealthyRange := "[1-3]"
			mhs.UnhealthyRange = &unhealthyRange
			return nil
		},
	}
}

// FuzzV1alpha3Conversion implements a fuzzer that is similar to the
// roundtrip test in cluster-api/util/conversion.FuzzTestFunc
func FuzzV1alpha3Conversion(data []byte) int {
	if len(data) < 100 {
		return 0
	}
	targetType := int(data[0])
	targetType = targetType % 11

	var hubName string
	var spokeName string
	var input utilconversion.FuzzTestFuncInput
	switch targetType {
	case 0:
		input = utilconversion.FuzzTestFuncInput{
			Hub:                &clusterv1.Cluster{},
			Spoke:              &Cluster{},
			SpokeAfterMutation: clusterSpokeAfterMutation,
			FuzzerFuncs:        []fuzzer.FuzzerFuncs{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.Cluster"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha3.Cluster"
	case 1:
		input = utilconversion.FuzzTestFuncInput{
			Hub:         &clusterv1.Machine{},
			Spoke:       &Machine{},
			FuzzerFuncs: []fuzzer.FuzzerFuncs{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.Machine"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha3.Machine"
	case 2:
		input = utilconversion.FuzzTestFuncInput{
			Hub:         &clusterv1.MachineSet{},
			Spoke:       &MachineSet{},
			FuzzerFuncs: []fuzzer.FuzzerFuncs{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.MachineSet"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha3.MachineSet"
	case 3:
		input = utilconversion.FuzzTestFuncInput{
			Hub:         &clusterv1.MachineDeployment{},
			Spoke:       &MachineDeployment{},
			FuzzerFuncs: []fuzzer.FuzzerFuncs{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.MachineDeployment"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha3.MachineDeployment"
	case 4:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.MachineHealthCheck{},
			Spoke: &MachineHealthCheck{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.MachineHealthCheck"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha3.MachineHealthCheck"
	case 5:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.Cluster{},
			Spoke: &v1alpha4.Cluster{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.Cluster"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha4.Cluster"
	case 6:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.ClusterClass{},
			Spoke: &v1alpha4.ClusterClass{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.ClusterClass"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha4.ClusterClass"
	case 7:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.Machine{},
			Spoke: &v1alpha4.Machine{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.Machine"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha4.Machine"
	case 8:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.MachineSet{},
			Spoke: &v1alpha4.MachineSet{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.MachineSet"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha4.MachineSet"
	case 9:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.MachineDeployment{},
			Spoke: &v1alpha4.MachineDeployment{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.MachineDeployment"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha4.MachineDeployment"
	case 10:
		input = utilconversion.FuzzTestFuncInput{
			Hub:   &clusterv1.MachineHealthCheck{},
			Spoke: &v1alpha4.MachineHealthCheck{},
		}
		hubName = "sigs.k8s.io/cluster-api/api/v1beta1.MachineHealthCheck"
		spokeName = "sigs.k8s.io/cluster-api/api/v1alpha4.MachineHealthCheck"
	default:
		return -1
	}
	doConversionRoundtrip(input, data[1:], hubName, spokeName)
	return 1
}

// performs the conversion roundtrip test
func doConversionRoundtrip(input utilconversion.FuzzTestFuncInput, data []byte, hubName, spokeName string) error {

	f := fuzz.NewConsumer(data)
	mhsFunc := customMachineHealth()
	f.AddFuncs(mhsFunc)

	if input.Scheme == nil {
		input.Scheme = scheme.Scheme
	}

	// Create the spoke and fuzz it
	spokeBefore := input.Spoke.DeepCopyObject().(conversion.Convertible)
	err := f.GenerateWithCustom(spokeBefore)
	if err != nil {
		return err
	}

	// Set some fields to avoid false positives
	setCustomFieldsSpoke(spokeBefore)

	// First convert spoke to hub
	hubCopy := input.Hub.DeepCopyObject().(conversion.Hub)
	err = spokeBefore.ConvertTo(hubCopy)
	if err != nil {
		return err
	}

	// Convert hub back to spoke and check if the resulting spoke is equal to the spoke before the round trip
	spokeAfter := input.Spoke.DeepCopyObject().(conversion.Convertible)
	err = spokeAfter.ConvertFrom(hubCopy)
	if err != nil {
		return err
	}

	// Remove data annotation eventually added by ConvertFrom for avoiding data loss in hub-spoke-hub round trips
	// NOTE: There are use case when we want to skip this operation, e.g. if the spoke object does not have ObjectMeta (e.g. kubeadm types).
	if !input.SkipSpokeAnnotationCleanup {
		metaAfter := spokeAfter.(metav1.Object)
		delete(metaAfter.GetAnnotations(), utilconversion.DataAnnotation)
	}

	if input.SpokeAfterMutation != nil {
		input.SpokeAfterMutation(spokeAfter)
	}

	if !apiequality.Semantic.DeepEqual(spokeBefore, spokeAfter) {
		panic(fmt.Sprintf(cmp.Diff(spokeBefore, spokeAfter)))
	}

	hubBefore := input.Hub.DeepCopyObject().(conversion.Hub)
	err = f.GenerateWithCustom(hubBefore)
	if err != nil {
		return err
	}

	// Validate machine deployment
	if _, ok := hubBefore.(*clusterv1.MachineDeployment); ok {
		err = validateMachineDeployment(hubBefore)
		if err != nil {
			return err
		}
	}
	// Validate ClusterClass
	if _, ok := hubBefore.(*clusterv1.ClusterClass); ok {
		err = validateClusterClass(hubBefore)
		if err != nil {
			return err
		}
	}

	// Set some fields to avoid false positives
	//setCustomFieldsHub(hubBefore)

	// First convert hub to spoke
	dstCopy := input.Spoke.DeepCopyObject().(conversion.Convertible)
	err = dstCopy.ConvertFrom(hubBefore)
	if err != nil {
		return err
	}

	// Convert spoke back to hub and check if the resulting hub is equal to the hub before the round trip
	hubAfter := input.Hub.DeepCopyObject().(conversion.Hub)
	err = dstCopy.ConvertTo(hubAfter)
	if err != nil {
		return err
	}

	if input.HubAfterMutation != nil {
		input.HubAfterMutation(hubAfter)
	}

	if !apiequality.Semantic.DeepEqual(hubBefore, hubAfter) {
		panic(fmt.Sprintf("Failed roundtrip for %s:\n\n%+v\n", hubName, cmp.Diff(hubBefore, hubAfter)))
	}
	return nil
}

func isValidUtf8(input []byte) bool {
	for _, b := range input {
		if int(b) > 127 {
			return false
		}
	}
	return true
}

// validates MachineDeployment
func validateMachineDeployment(hubBefore conversion.Hub) error {
	if len(hubBefore.(*clusterv1.MachineDeployment).Status.Conditions) == 0 {
		return fmt.Errorf("No conditions were created")
	}
	if _, ok := hubBefore.(*clusterv1.MachineDeployment); ok {
		for i, _ := range hubBefore.(*clusterv1.MachineDeployment).Status.Conditions {
			cond := hubBefore.(*clusterv1.MachineDeployment).Status.Conditions[i]
			if !isValidUtf8([]byte(cond.Message)) {
				return fmt.Errorf("Invalid utf8")
			}
			if !isValidUtf8([]byte(cond.Type)) {
				return fmt.Errorf("Invalid utf8")
			}
			if !isValidUtf8([]byte(cond.Reason)) {
				return fmt.Errorf("Invalid utf8")
			}
			if !isValidUtf8([]byte(cond.Severity)) {
				return fmt.Errorf("Invalid utf8")
			}
			if !isValidUtf8([]byte(cond.Status)) {
				return fmt.Errorf("Invalid utf8")
			}
		}
	}
	return nil
}

func validateClusterClass(hubBefore conversion.Hub) error {
	// TODO: Randomize this
	mu := hubBefore.(*clusterv1.ClusterClass).Spec.ControlPlane.MachineHealthCheck.MaxUnhealthy
	mu.StrVal = ""
	mu.Type = 2
	mu.IntVal = 1
	return nil
}

// validates a cluster to prevent false positives.
func validateCluster(hubBefore conversion.Hub, f *fuzz.ConsumeFuzzer) error {
	layout := "Mon, 01/02/06, 03:04PM"
	timeStr := "Thu, 02/03/07, 04:05PM"
	rolloutAfter, err := time.Parse(layout, timeStr)
	if err != nil {
		return err
	}
	newTime := metav1.NewTime(rolloutAfter)

	clusterTopology := hubBefore.(*clusterv1.Cluster).Spec.Topology
	if clusterTopology == nil {
		return fmt.Errorf("cp is nil")
	}
	clusterTopology.RolloutAfter = &newTime

	for _, md := range clusterTopology.Workers.MachineDeployments {
		if len(md.Metadata.Labels) == 0 {
			return fmt.Errorf("No labels created")
		}
		if len(md.Variables.Overrides) == 0 {
			return fmt.Errorf("No overrides created")
		}
	}

	for _, v := range clusterTopology.Variables {
		if len(v.Value.Raw) == 0 {
			return fmt.Errorf("empty value")
		}
	}

	if len(clusterTopology.Variables) == 0 {
		return fmt.Errorf("No value created")
	}

	for _, md := range clusterTopology.Workers.MachineDeployments {
		for _, o := range md.Variables.Overrides {
			if len(o.Value.Raw) == 0 {
				return fmt.Errorf("empty value")
			}
		}
	}

	if len(clusterTopology.ControlPlane.Metadata.Labels) == 0 {
		return fmt.Errorf("No controlplane labels created")
	}

	if len(clusterTopology.ControlPlane.Metadata.Annotations) == 0 {
		return fmt.Errorf("No controlplane annotations created")
	}
	return nil
}

// sets a few fields of each type to prevent false positives.
func setCustomFieldsSpoke(spokeBefore conversion.Convertible) {
	if _, ok := spokeBefore.(*Cluster); ok {
		spokeBefore.(*Cluster).TypeMeta.Kind = ""
		spokeBefore.(*Cluster).TypeMeta.APIVersion = ""
		return
	}
	if _, ok := spokeBefore.(*MachineHealthCheck); ok {
		spokeBefore.(*MachineHealthCheck).TypeMeta.Kind = ""
		spokeBefore.(*MachineHealthCheck).TypeMeta.APIVersion = ""
		return
	}
	if _, ok := spokeBefore.(*MachineSet); ok {
		spokeBefore.(*MachineSet).TypeMeta.Kind = ""
		spokeBefore.(*MachineSet).TypeMeta.APIVersion = ""
		spokeBefore.(*MachineSet).Spec.Template.ObjectMeta.Name = ""
		spokeBefore.(*MachineSet).Spec.Template.ObjectMeta.GenerateName = ""
		spokeBefore.(*MachineSet).Spec.Template.ObjectMeta.Namespace = ""
		spokeBefore.(*MachineSet).Spec.Template.ObjectMeta.OwnerReferences = nil
		spokeBefore.(*MachineSet).Spec.Template.Spec.Bootstrap.Data = nil
		return
	}
	if _, ok := spokeBefore.(*MachineDeployment); ok {
		spokeBefore.(*MachineDeployment).TypeMeta.Kind = ""
		spokeBefore.(*MachineDeployment).TypeMeta.APIVersion = ""
		spokeBefore.(*MachineDeployment).Spec.Template.ObjectMeta.Name = ""
		spokeBefore.(*MachineDeployment).Spec.Template.ObjectMeta.GenerateName = ""
		spokeBefore.(*MachineDeployment).Spec.Template.ObjectMeta.Namespace = ""
		spokeBefore.(*MachineDeployment).Spec.Template.ObjectMeta.OwnerReferences = nil
		spokeBefore.(*MachineDeployment).Spec.Template.Spec.Bootstrap.Data = nil
		return
	}
	if _, ok := spokeBefore.(*Machine); ok {
		spokeBefore.(*Machine).TypeMeta.Kind = ""
		spokeBefore.(*Machine).TypeMeta.APIVersion = ""
		spokeBefore.(*Machine).Spec.Bootstrap.Data = nil
		spokeBefore.(*Machine).Status.Version = nil
		return
	}
}

// sets a few fields of each type to prevent false positives.
func setCustomFieldsHub(hubBefore conversion.Hub) {
	if _, ok := hubBefore.(*clusterv1.Cluster); ok {
		hubBefore.(*clusterv1.Cluster).TypeMeta.Kind = ""
		hubBefore.(*clusterv1.Cluster).TypeMeta.APIVersion = ""
		return
	}
	if _, ok := hubBefore.(*clusterv1.MachineHealthCheck); ok {
		hubBefore.(*clusterv1.MachineHealthCheck).TypeMeta.Kind = ""
		hubBefore.(*clusterv1.MachineHealthCheck).TypeMeta.APIVersion = ""
		return
	}
	if _, ok := hubBefore.(*clusterv1.Machine); ok {
		hubBefore.(*clusterv1.Machine).TypeMeta.Kind = ""
		hubBefore.(*clusterv1.Machine).TypeMeta.APIVersion = ""
		return
	}
	if _, ok := hubBefore.(*clusterv1.MachineSet); ok {
		hubBefore.(*clusterv1.MachineSet).TypeMeta.Kind = ""
		hubBefore.(*clusterv1.MachineSet).TypeMeta.APIVersion = ""
		return
	}
	if _, ok := hubBefore.(*clusterv1.MachineDeployment); ok {
		hubBefore.(*clusterv1.MachineDeployment).TypeMeta.Kind = ""
		hubBefore.(*clusterv1.MachineDeployment).TypeMeta.APIVersion = ""
		return
	}
}

func clusterSpokeAfterMutation(c conversion.Convertible) {
	cluster := c.(*Cluster)

	// Create a temporary 0-length slice using the same underlying array as cluster.Status.Conditions to avoid
	// allocations.
	tmp := cluster.Status.Conditions[:0]

	for i := range cluster.Status.Conditions {
		condition := cluster.Status.Conditions[i]

		// Keep everything that is not ControlPlaneInitializedCondition
		if condition.Type != ConditionType(clusterv1.ControlPlaneInitializedCondition) {
			tmp = append(tmp, condition)
		}
	}

	// Point cluster.Status.Conditions and our slice that does not have ControlPlaneInitializedCondition
	cluster.Status.Conditions = tmp
}
