// Copyright 2025 the cncf-fuzzing authors
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

package testutils

import (
	"fmt"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	k8sv1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	clonev1 "kubevirt.io/api/clone/v1beta1"
	virtv1 "kubevirt.io/api/core/v1"
	poolv1 "kubevirt.io/api/pool/v1beta1"
	snapshotv1 "kubevirt.io/api/snapshot/v1beta1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
)

const (
	validChars      = "abcdefghijklmnopqrstuvwxyz0123456789"
	validStartChars = "abcdefghijklmnopqrstuvwxyz"
	validLabelChars = "abcdefghijklmnopqrstuvwxyz0123456789-_."
	minNameLength   = 5
	maxNameLength   = 63
	minLabelLength  = 3
	maxLabelLength  = 63
)

// generateValidK8sName generates a DNS-1123 subdomain compliant name
// DNS-1123 subdomain must consist of lowercase alphanumeric characters, '-' or '.',
// and must start and end with an alphanumeric character
func generateValidK8sName(c gofuzzheaders.Continue, prefix string) string {
	length := minNameLength + c.Intn(maxNameLength-minNameLength)

	// Ensure length is positive
	if length <= 0 {
		length = minNameLength
	}

	// If prefix is too long, truncate it to fit within the length
	if len(prefix) >= length {
		// Ensure we don't try to slice with negative or out of bounds index
		if length > len(prefix) {
			length = len(prefix)
		}
		if length < 0 {
			length = 0
		}
		return prefix[:length]
	}

	// Start with prefix and a valid start character
	name := prefix + "-"
	startIdx := c.Intn(len(validStartChars))
	if startIdx < 0 || startIdx >= len(validStartChars) {
		startIdx = 0
	}
	name += string(validStartChars[startIdx])

	// Calculate remaining length, accounting for the final character we'll add
	remainingLength := length - len(prefix) - 2
	if remainingLength < 0 {
		remainingLength = 0
	}

	// Add random valid characters
	for i := 0; i < remainingLength; i++ {
		idx := c.Intn(len(validChars))
		if idx < 0 || idx >= len(validChars) {
			idx = 0
		}
		name += string(validChars[idx])
	}

	// Only add final character if we have room
	if len(name) < length {
		endIdx := c.Intn(len(validChars))
		if endIdx < 0 || endIdx >= len(validChars) {
			endIdx = 0
		}
		name += string(validChars[endIdx])
	}

	return name
}

// generateValidK8sLabel generates a valid Kubernetes label value
// Labels can be empty or consist of alphanumeric, '-', '_', '.'
// and must start and end with alphanumeric
func generateValidK8sLabel(c gofuzzheaders.Continue, prefix string) string {
	// Sometimes generate empty label (valid)
	if c.Intn(10) == 0 {
		return ""
	}

	length := minLabelLength + c.Intn(maxLabelLength-minLabelLength)

	// Ensure length is positive
	if length <= 0 {
		length = minLabelLength
	}

	// If prefix is already longer than or equal to desired length, just return it truncated
	if len(prefix) >= length {
		// Ensure we don't try to slice with negative or out of bounds index
		if length > len(prefix) {
			length = len(prefix)
		}
		if length < 0 {
			length = 0
		}
		return prefix[:length]
	}

	// Start with valid character
	label := prefix
	if len(prefix) == 0 {
		startIdx := c.Intn(len(validStartChars))
		if startIdx < 0 || startIdx >= len(validStartChars) {
			startIdx = 0
		}
		label = string(validStartChars[startIdx])
	}

	// Calculate remaining length needed, accounting for the final character we'll add
	remainingLength := length - len(label) - 1
	if remainingLength < 0 {
		remainingLength = 0
	}

	// Add random valid characters
	for i := 0; i < remainingLength; i++ {
		idx := c.Intn(len(validLabelChars))
		if idx < 0 || idx >= len(validLabelChars) {
			idx = 0
		}
		label += string(validLabelChars[idx])
	}

	// Only add final character if we have room
	if len(label) < length {
		endIdx := c.Intn(len(validChars))
		if endIdx < 0 || endIdx >= len(validChars) {
			endIdx = 0
		}
		label += string(validChars[endIdx])
	}

	return label
}

// CustomObjectMetaFuzzer creates a custom fuzzer for ObjectMeta that generates
// valid DNS-1123 compliant names and labels
func CustomObjectMetaFuzzer(namespace string) func(*metav1.ObjectMeta, gofuzzheaders.Continue) {
	return func(objectMeta *metav1.ObjectMeta, c gofuzzheaders.Continue) {
		objectMeta.Name = generateValidK8sName(c, "resource")
		objectMeta.Namespace = namespace

		// Generate valid labels
		objectMeta.Labels = map[string]string{
			"app.kubernetes.io/name":      generateValidK8sLabel(c, "kubevirt"),
			"app.kubernetes.io/component": generateValidK8sLabel(c, "virt"),
			"kubevirt.io/test":            "fuzzer",
		}

		// Generate valid annotations
		objectMeta.Annotations = map[string]string{
			"kubevirt.io/latest-observed-api-version": virtv1.ApiLatestVersion,
			"description": generateValidK8sLabel(c, "test"),
		}

		// Set generation and resource version
		objectMeta.Generation = c.Int63()
		objectMeta.ResourceVersion = fmt.Sprintf("%d", c.Int63())
	}
}

// CustomPodFuzzer creates a custom fuzzer for Pods with valid containers and specs
func CustomPodFuzzer() func(*k8sv1.Pod, gofuzzheaders.Continue) {
	return func(pod *k8sv1.Pod, c gofuzzheaders.Continue) {
		// Let ObjectMeta fuzzer handle metadata
		// Just ensure containers are valid
		if len(pod.Spec.Containers) == 0 {
			pod.Spec.Containers = []k8sv1.Container{
				{
					Name:  "compute",
					Image: "kubevirt/virt-launcher:latest",
					Resources: k8sv1.ResourceRequirements{
						Requests: k8sv1.ResourceList{
							k8sv1.ResourceMemory: resource.MustParse("64Mi"),
							k8sv1.ResourceCPU:    resource.MustParse("100m"),
						},
					},
				},
			}
		} else {
			// Fix existing containers
			for i := range pod.Spec.Containers {
				if pod.Spec.Containers[i].Name == "" {
					pod.Spec.Containers[i].Name = fmt.Sprintf("container-%d", i)
				}
				if pod.Spec.Containers[i].Image == "" {
					pod.Spec.Containers[i].Image = "kubevirt/virt-launcher:latest"
				}
			}
		}

		// Ensure valid restart policy
		if pod.Spec.RestartPolicy == "" {
			restartPolicies := []k8sv1.RestartPolicy{
				k8sv1.RestartPolicyAlways,
				k8sv1.RestartPolicyOnFailure,
				k8sv1.RestartPolicyNever,
			}
			pod.Spec.RestartPolicy = restartPolicies[c.Intn(len(restartPolicies))]
		}
	}
}

// CustomPVCFuzzer creates a custom fuzzer for PersistentVolumeClaims with valid specs
func CustomPVCFuzzer() func(*k8sv1.PersistentVolumeClaim, gofuzzheaders.Continue) {
	return func(pvc *k8sv1.PersistentVolumeClaim, c gofuzzheaders.Continue) {
		// Ensure valid storage request
		if pvc.Spec.Resources.Requests == nil {
			pvc.Spec.Resources.Requests = k8sv1.ResourceList{
				k8sv1.ResourceStorage: resource.MustParse("1Gi"),
			}
		}

		// Ensure valid access modes
		if len(pvc.Spec.AccessModes) == 0 {
			accessModes := []k8sv1.PersistentVolumeAccessMode{
				k8sv1.ReadWriteOnce,
				k8sv1.ReadOnlyMany,
				k8sv1.ReadWriteMany,
			}
			pvc.Spec.AccessModes = []k8sv1.PersistentVolumeAccessMode{
				accessModes[c.Intn(len(accessModes))],
			}
		}
	}
}

// CustomDataVolumeFuzzer creates a custom fuzzer for DataVolumes with valid specs
func CustomDataVolumeFuzzer() func(*cdiv1.DataVolume, gofuzzheaders.Continue) {
	return func(dv *cdiv1.DataVolume, c gofuzzheaders.Continue) {
		// Ensure valid PVC spec
		if dv.Spec.PVC == nil {
			storageRequest := resource.MustParse("1Gi")
			dv.Spec.PVC = &k8sv1.PersistentVolumeClaimSpec{
				AccessModes: []k8sv1.PersistentVolumeAccessMode{k8sv1.ReadWriteOnce},
				Resources: k8sv1.VolumeResourceRequirements{
					Requests: k8sv1.ResourceList{
						k8sv1.ResourceStorage: storageRequest,
					},
				},
			}
		}

		// Ensure valid source
		if dv.Spec.Source == nil {
			registryURL := "docker://kubevirt/fedora-cloud-container-disk-demo"
			sources := []cdiv1.DataVolumeSource{
				{HTTP: &cdiv1.DataVolumeSourceHTTP{URL: "http://example.com/image.img"}},
				{Registry: &cdiv1.DataVolumeSourceRegistry{URL: &registryURL}},
				{PVC: &cdiv1.DataVolumeSourcePVC{Namespace: "default", Name: "source-pvc"}},
			}
			dv.Spec.Source = &sources[c.Intn(len(sources))]
		}
	}
}

// CustomVMIFuzzer creates a custom fuzzer for VirtualMachineInstance with valid specs
func CustomVMIFuzzer(namespace string) func(*virtv1.VirtualMachineInstance, gofuzzheaders.Continue) {
	return func(vmi *virtv1.VirtualMachineInstance, c gofuzzheaders.Continue) {
		// Ensure valid domain spec
		if vmi.Spec.Domain.Resources.Requests == nil {
			vmi.Spec.Domain.Resources.Requests = k8sv1.ResourceList{
				k8sv1.ResourceMemory: resource.MustParse("64Mi"),
			}
		}

		// Ensure at least one disk and volume
		if len(vmi.Spec.Domain.Devices.Disks) == 0 {
			vmi.Spec.Domain.Devices.Disks = []virtv1.Disk{
				{
					Name: "disk0",
					DiskDevice: virtv1.DiskDevice{
						Disk: &virtv1.DiskTarget{
							Bus: virtv1.DiskBusVirtio,
						},
					},
				},
			}
		}

		if len(vmi.Spec.Volumes) == 0 {
			vmi.Spec.Volumes = []virtv1.Volume{
				{
					Name: "disk0",
					VolumeSource: virtv1.VolumeSource{
						ContainerDisk: &virtv1.ContainerDiskSource{
							Image: "kubevirt/cirros-container-disk-demo",
						},
					},
				},
			}
		}

		// Ensure network is set
		if len(vmi.Spec.Networks) == 0 {
			vmi.Spec.Networks = []virtv1.Network{
				{
					Name: "default",
					NetworkSource: virtv1.NetworkSource{
						Pod: &virtv1.PodNetwork{},
					},
				},
			}
		}

		if len(vmi.Spec.Domain.Devices.Interfaces) == 0 {
			vmi.Spec.Domain.Devices.Interfaces = []virtv1.Interface{
				{
					Name: "default",
					InterfaceBindingMethod: virtv1.InterfaceBindingMethod{
						Masquerade: &virtv1.InterfaceMasquerade{},
					},
				},
			}
		}
	}
}

// CustomVMFuzzer creates a custom fuzzer for VirtualMachine with valid specs
func CustomVMFuzzer(namespace string) func(*virtv1.VirtualMachine, gofuzzheaders.Continue) {
	return func(vm *virtv1.VirtualMachine, c gofuzzheaders.Continue) {
		// Ensure template is set
		if vm.Spec.Template == nil {
			vm.Spec.Template = &virtv1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubevirt.io/vm": vm.Name,
					},
				},
				Spec: virtv1.VirtualMachineInstanceSpec{
					Domain: virtv1.DomainSpec{
						Resources: virtv1.ResourceRequirements{
							Requests: k8sv1.ResourceList{
								k8sv1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
						Devices: virtv1.Devices{
							Disks: []virtv1.Disk{
								{
									Name: "disk0",
									DiskDevice: virtv1.DiskDevice{
										Disk: &virtv1.DiskTarget{
											Bus: virtv1.DiskBusVirtio,
										},
									},
								},
							},
						},
					},
					Volumes: []virtv1.Volume{
						{
							Name: "disk0",
							VolumeSource: virtv1.VolumeSource{
								ContainerDisk: &virtv1.ContainerDiskSource{
									Image: "kubevirt/cirros-container-disk-demo",
								},
							},
						},
					},
				},
			}
		}

		// Apply VMI fuzzer to template spec
		CustomVMIFuzzer(namespace)(&virtv1.VirtualMachineInstance{
			Spec: vm.Spec.Template.Spec,
		}, c)

		// Set running state randomly
		running := c.RandBool()
		vm.Spec.Running = &running
	}
}

// CustomNodeFuzzer creates a custom fuzzer for Nodes with valid names and labels
func CustomNodeFuzzer() func(*k8sv1.Node, gofuzzheaders.Continue) {
	return func(node *k8sv1.Node, c gofuzzheaders.Continue) {
		// Ensure valid node name
		if node.Name == "" {
			node.Name = generateValidK8sName(c, "node")
		}

		// Ensure standard node labels
		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		node.Labels["kubernetes.io/hostname"] = node.Name
		node.Labels["kubernetes.io/os"] = "linux"

		// Add capacity and allocatable if missing
		if node.Status.Capacity == nil {
			node.Status.Capacity = k8sv1.ResourceList{
				k8sv1.ResourceCPU:    resource.MustParse("4"),
				k8sv1.ResourceMemory: resource.MustParse("8Gi"),
				k8sv1.ResourcePods:   resource.MustParse("110"),
			}
		}

		if node.Status.Allocatable == nil {
			node.Status.Allocatable = k8sv1.ResourceList{
				k8sv1.ResourceCPU:    resource.MustParse("4"),
				k8sv1.ResourceMemory: resource.MustParse("8Gi"),
				k8sv1.ResourcePods:   resource.MustParse("110"),
			}
		}

		// Set node to ready
		node.Status.Conditions = []k8sv1.NodeCondition{
			{
				Type:   k8sv1.NodeReady,
				Status: k8sv1.ConditionTrue,
			},
		}
	}
}

// CustomVMIMigrationFuzzer creates a custom fuzzer for VirtualMachineInstanceMigration
func CustomVMIMigrationFuzzer(namespace string) func(*virtv1.VirtualMachineInstanceMigration, gofuzzheaders.Continue) {
	return func(migration *virtv1.VirtualMachineInstanceMigration, c gofuzzheaders.Continue) {
		// Ensure valid VMI name reference
		if migration.Spec.VMIName == "" {
			migration.Spec.VMIName = generateValidK8sName(c, "vmi")
		}
	}
}

// CustomPodDisruptionBudgetFuzzer creates a custom fuzzer for PodDisruptionBudget
func CustomPodDisruptionBudgetFuzzer() func(*policyv1.PodDisruptionBudget, gofuzzheaders.Continue) {
	return func(pdb *policyv1.PodDisruptionBudget, c gofuzzheaders.Continue) {
		// Ensure valid selector
		if pdb.Spec.Selector == nil {
			pdb.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubevirt.io/domain": generateValidK8sLabel(c, "vmi"),
				},
			}
		}

		// Ensure valid min available
		if pdb.Spec.MinAvailable == nil && pdb.Spec.MaxUnavailable == nil {
			minAvailable := intstr.FromInt(1)
			pdb.Spec.MinAvailable = &minAvailable
		}
	}
}

// CustomNodeWithTaintsFuzzer creates a custom fuzzer for Nodes with evacuation taints
func CustomNodeWithTaintsFuzzer() func(*k8sv1.Node, gofuzzheaders.Continue) {
	return func(node *k8sv1.Node, c gofuzzheaders.Continue) {
		// First apply standard node fuzzer
		CustomNodeFuzzer()(node, c)

		// Add evacuation taints randomly
		if c.RandBool() {
			taintEffects := []k8sv1.TaintEffect{
				k8sv1.TaintEffectNoSchedule,
				k8sv1.TaintEffectNoExecute,
			}
			node.Spec.Taints = []k8sv1.Taint{
				{
					Key:    "kubevirt.io/drain",
					Value:  "draining",
					Effect: taintEffects[c.Intn(len(taintEffects))],
				},
			}
		}
	}
}

// CustomVMPoolFuzzer creates a custom fuzzer for VirtualMachinePool
func CustomVMPoolFuzzer(namespace string) func(*poolv1.VirtualMachinePool, gofuzzheaders.Continue) {
	return func(pool *poolv1.VirtualMachinePool, c gofuzzheaders.Continue) {
		// Set namespace and name manually
		pool.Namespace = namespace

		// Ensure valid name
		if pool.Name == "" {
			pool.Name = generateValidK8sName(c, "vmpool")
		}

		// Set basic ObjectMeta fields
		if pool.UID == "" {
			pool.UID = "test-uid"
		}
		if pool.ResourceVersion == "" {
			pool.ResourceVersion = "1"
		}

		// Ensure valid replicas
		if pool.Spec.Replicas == nil {
			replicas := int32(1 + c.Intn(3))
			pool.Spec.Replicas = &replicas
		}

		// Ensure valid selector
		if pool.Spec.Selector == nil {
			pool.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubevirt.io/vmpool": pool.Name,
				},
			}
		}

		// Ensure valid VM template
		if pool.Spec.VirtualMachineTemplate == nil {
			running := false
			pool.Spec.VirtualMachineTemplate = &poolv1.VirtualMachineTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kubevirt.io/vmpool": pool.Name,
					},
				},
				Spec: virtv1.VirtualMachineSpec{
					Running: &running,
					Template: &virtv1.VirtualMachineInstanceTemplateSpec{
						Spec: virtv1.VirtualMachineInstanceSpec{
							Domain: virtv1.DomainSpec{
								Resources: virtv1.ResourceRequirements{
									Requests: k8sv1.ResourceList{
										k8sv1.ResourceMemory: resource.MustParse("64Mi"),
									},
								},
							},
						},
					},
				},
			}
		}
	}
}

// CustomVMCloneFuzzer creates a custom fuzzer for VirtualMachineClone
func CustomVMCloneFuzzer(namespace string) func(*clonev1.VirtualMachineClone, gofuzzheaders.Continue) {
	return func(vmClone *clonev1.VirtualMachineClone, c gofuzzheaders.Continue) {
		// Ensure valid source reference
		if vmClone.Spec.Source == nil {
			vmClone.Spec.Source = &k8sv1.TypedLocalObjectReference{
				APIGroup: &virtv1.SchemeGroupVersion.Group,
				Kind:     "VirtualMachine",
				Name:     generateValidK8sName(c, "source-vm"),
			}
		}

		// Ensure valid target name
		if vmClone.Spec.Target == nil {
			vmClone.Spec.Target = &k8sv1.TypedLocalObjectReference{
				APIGroup: &virtv1.SchemeGroupVersion.Group,
				Kind:     "VirtualMachine",
				Name:     generateValidK8sName(c, "target-vm"),
			}
		}
	}
}

// CustomVMIReplicaSetFuzzer creates a custom fuzzer for VirtualMachineInstanceReplicaSet
func CustomVMIReplicaSetFuzzer(namespace string) func(*virtv1.VirtualMachineInstanceReplicaSet, gofuzzheaders.Continue) {
	return func(rs *virtv1.VirtualMachineInstanceReplicaSet, c gofuzzheaders.Continue) {
		// Ensure metadata is valid
		rs.Namespace = namespace
		rs.Name = generateValidK8sName(c, "rs")
		if rs.Labels == nil {
			rs.Labels = make(map[string]string)
		}
		rs.Labels["app"] = generateValidK8sLabel(c, "app")

		// Ensure replicas is reasonable
		if rs.Spec.Replicas == nil {
			replicas := int32(c.Intn(10))
			rs.Spec.Replicas = &replicas
		}

		// Ensure template is not nil
		if rs.Spec.Template == nil {
			rs.Spec.Template = &virtv1.VirtualMachineInstanceTemplateSpec{}
		}

		// Ensure template has valid labels
		if rs.Spec.Template.ObjectMeta.Labels == nil {
			rs.Spec.Template.ObjectMeta.Labels = make(map[string]string)
		}
		rs.Spec.Template.ObjectMeta.Labels["app"] = generateValidK8sLabel(c, "app")

		// Ensure selector matches template labels
		if rs.Spec.Selector == nil {
			rs.Spec.Selector = &metav1.LabelSelector{}
		}
		rs.Spec.Selector.MatchLabels = rs.Spec.Template.ObjectMeta.Labels

		// Ensure template spec is valid
		if rs.Spec.Template.Spec.Domain.Devices.Disks == nil {
			rs.Spec.Template.Spec.Domain.Devices.Disks = []virtv1.Disk{
				{
					Name: generateValidK8sName(c, "disk"),
					DiskDevice: virtv1.DiskDevice{
						Disk: &virtv1.DiskTarget{
							Bus: "virtio",
						},
					},
				},
			}
		}

		if rs.Spec.Template.Spec.Volumes == nil {
			rs.Spec.Template.Spec.Volumes = []virtv1.Volume{
				{
					Name: rs.Spec.Template.Spec.Domain.Devices.Disks[0].Name,
					VolumeSource: virtv1.VolumeSource{
						ContainerDisk: &virtv1.ContainerDiskSource{
							Image: "kubevirt/fedora-cloud-container-disk-demo",
						},
					},
				},
			}
		}
	}
}

// CustomVMSnapshotFuzzer creates a custom fuzzer for VirtualMachineSnapshot
func CustomVMSnapshotFuzzer(namespace string) func(*snapshotv1.VirtualMachineSnapshot, gofuzzheaders.Continue) {
	return func(vmSnapshot *snapshotv1.VirtualMachineSnapshot, c gofuzzheaders.Continue) {
		// Ensure valid metadata
		vmSnapshot.Namespace = namespace
		vmSnapshot.Name = generateValidK8sName(c, "snapshot")
		if vmSnapshot.Labels == nil {
			vmSnapshot.Labels = make(map[string]string)
		}

		// Ensure valid source reference
		if vmSnapshot.Spec.Source.Name == "" {
			vmSnapshot.Spec.Source.Name = generateValidK8sName(c, "vm")
		}
		if vmSnapshot.Spec.Source.Kind == "" {
			vmSnapshot.Spec.Source.Kind = "VirtualMachine"
		}
		if vmSnapshot.Spec.Source.APIGroup == nil {
			apiGroup := virtv1.SchemeGroupVersion.Group
			vmSnapshot.Spec.Source.APIGroup = &apiGroup
		}

		// Set deletion policy if nil
		if vmSnapshot.Spec.DeletionPolicy == nil {
			deletionPolicy := snapshotv1.VirtualMachineSnapshotContentDelete
			vmSnapshot.Spec.DeletionPolicy = &deletionPolicy
		}
	}
}

// CustomVMSnapshotContentFuzzer creates a custom fuzzer for VirtualMachineSnapshotContent
func CustomVMSnapshotContentFuzzer(namespace string) func(*snapshotv1.VirtualMachineSnapshotContent, gofuzzheaders.Continue) {
	return func(content *snapshotv1.VirtualMachineSnapshotContent, c gofuzzheaders.Continue) {
		// Ensure valid metadata
		content.Namespace = namespace
		content.Name = generateValidK8sName(c, "snapshot-content")
		if content.Labels == nil {
			content.Labels = make(map[string]string)
		}

		// Ensure valid source reference
		if content.Spec.Source.VirtualMachine != nil && content.Spec.Source.VirtualMachine.Name == "" {
			content.Spec.Source.VirtualMachine.Name = generateValidK8sName(c, "vm")
		}

		// Ensure valid snapshot reference
		if content.Spec.VirtualMachineSnapshotName == nil {
			snapshotName := generateValidK8sName(c, "snapshot")
			content.Spec.VirtualMachineSnapshotName = &snapshotName
		}
	}
}

// GetCustomFuzzFuncs returns a slice of custom fuzz functions for the given namespace
func GetCustomFuzzFuncs(namespace string) []interface{} {
	return []interface{}{
		CustomObjectMetaFuzzer(namespace),
		CustomPodFuzzer(),
		CustomPVCFuzzer(),
		CustomDataVolumeFuzzer(),
		CustomVMIFuzzer(namespace),
		CustomVMFuzzer(namespace),
		CustomNodeFuzzer(),
	}
}
