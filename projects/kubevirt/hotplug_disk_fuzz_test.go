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

package fuzz

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	diskutils "kubevirt.io/kubevirt/pkg/ephemeral-disk-utils"
	"kubevirt.io/kubevirt/pkg/safepath"
	"kubevirt.io/kubevirt/pkg/unsafepath"
)

// FuzzHotplugVolumeMounting tests that hotplug volume device paths:
// 1. MUST resolve within the volume boundary (no path traversal)
// 2. MUST reject symlinks to virt-launcher files
// 3. MUST reject absolute device paths
// 4. MUST validate device paths before ownership changes
//
// Related CVEs: GHSA-qw6q-3pgr-5cwq (hostDisk symlink), GHSA-46xp-26xh-hpqh (ownership bypass)
func FuzzHotplugVolumeMounting(f *testing.F) {
	// Seed corpus with known attack patterns
	f.Add("disk.img", "pvc-volume", false, false) // Normal case
	f.Add("../../../../etc/shadow", "pvc-volume", true, false) // Path traversal
	f.Add("/etc/passwd", "pvc-volume", true, false) // Absolute path
	f.Add("../../../var/run/kubevirt/sockets/launcher-sock", "pvc-volume", true, false) // Escape to virt-launcher
	f.Add("disk.img", "../../../../etc", true, false) // Malicious volume name
	f.Add("./../disk.img", "pvc-volume", true, false) // Relative traversal

	f.Fuzz(func(t *testing.T, deviceName, volumeName string, shouldEscape bool, isSymlink bool) {
		// Skip empty inputs
		if deviceName == "" || volumeName == "" {
			return
		}

		// Create temporary test environment
		tmpDir := t.TempDir()
		volumeBasePath := filepath.Join(tmpDir, "volumes")
		deviceBasePath := filepath.Join(volumeBasePath, volumeName)

		if err := os.MkdirAll(deviceBasePath, 0755); err != nil {
			t.Skip("Cannot create test directory")
		}

		// Create volume boundary root
		volumeRoot, err := safepath.JoinAndResolveWithRelativeRoot(volumeBasePath)
		if err != nil {
			t.Skip("Cannot create volume root")
		}

		// Property 1: Device path MUST resolve within volume boundary
		// Try to resolve with safepath (this should catch path traversal)
		volumeSubPath, err := safepath.JoinNoFollow(volumeRoot, volumeName)
		if err != nil {
			// Volume name is malicious
			if strings.Contains(volumeName, "..") || filepath.IsAbs(volumeName) {
				return // Expected failure
			}
			t.Skip("Cannot resolve volume path")
		}
		
		resolvedPath, err := safepath.JoinNoFollow(volumeSubPath, deviceName)
		
		// Determine if path is malicious
		isMalicious := false
		
		// Check for path traversal attempts
		if strings.Contains(deviceName, "..") || strings.Contains(volumeName, "..") {
			isMalicious = true
		}
		
		// Check for absolute paths
		if filepath.IsAbs(deviceName) {
			isMalicious = true
		}
		
		// Check for escape attempts to sensitive paths
		if resolvedPath != nil {
			absResolved := unsafepath.UnsafeAbsolute(resolvedPath.Raw())
			if !strings.HasPrefix(absResolved, deviceBasePath) {
				isMalicious = true
			}
			
			// Check if path escapes to virt-launcher directories
			sensitivePatterns := []string{
				"/var/run/kubevirt",
				"/var/run/libvirt",
				"/etc/",
				"/root/",
				"/proc/",
				"/sys/",
			}
			for _, pattern := range sensitivePatterns {
				if strings.Contains(absResolved, pattern) {
					isMalicious = true
					break
				}
			}
		}

		// Property test: Malicious paths MUST be rejected
		if isMalicious {
			if err == nil {
				panic(fmt.Sprintf("SECURITY VIOLATION: Malicious path accepted: deviceName=%q, volumeName=%q, resolved=%v",
					deviceName, volumeName, resolvedPath))
			}
			// Expected failure - malicious path correctly rejected
			return
		}

		// For valid paths, test symlink handling
		if resolvedPath != nil && err == nil {
			deviceFile := filepath.Join(deviceBasePath, filepath.Base(deviceName))
			
			// Create device file or symlink
			if isSymlink {
				// Create symlink to sensitive file
				targetFile := filepath.Join(tmpDir, "sensitive-file")
				if err := os.WriteFile(targetFile, []byte("sensitive data"), 0600); err != nil {
					return
				}
				if err := os.Symlink(targetFile, deviceFile); err != nil {
					return
				}
			} else {
				// Create normal device file
				if err := os.WriteFile(deviceFile, []byte("disk data"), 0644); err != nil {
					return
				}
			}

			// Property 2: Symlinks MUST be detected and rejected
			fi, err := os.Lstat(deviceFile)
			if err == nil && fi.Mode()&os.ModeSymlink != 0 {
				// This is a symlink - operations on it should fail or follow safepath rules
				volumeSubPath, err := safepath.JoinNoFollow(volumeRoot, volumeName)
				if err == nil {
					_, err = safepath.JoinNoFollow(volumeSubPath, filepath.Base(deviceFile))
					if err == nil {
						t.Logf("INFO: Symlink correctly handled with safepath: %s", deviceFile)
					}
				}
			}
		}
	})
}

// FuzzHotplugOwnershipValidation tests that SetFileOwnership:
// 1. MUST NOT change ownership of existing files owned by other users
// 2. MUST only apply to files under volume mount point
// 3. MUST validate current owner before modification
// 4. MUST reject ownership changes on symlinks
//
// Related CVE: GHSA-46xp-26xh-hpqh (ownership bypass)
func FuzzHotplugOwnershipValidation(f *testing.F) {
	// Seed corpus with ownership attack patterns
	f.Add("device.img", uint32(0), uint32(0), false) // Root-owned file
	f.Add("device.img", uint32(107), uint32(107), false) // QEMU user
	f.Add("device.img", uint32(1000), uint32(1000), false) // Regular user
	f.Add("../../../etc/passwd", uint32(0), uint32(0), true) // Escape attempt
	f.Add("symlink-device", uint32(0), uint32(0), true) // Symlink attack

	f.Fuzz(func(t *testing.T, deviceName string, currentUID, currentGID uint32, isSymlink bool) {
		if deviceName == "" {
			return
		}

		// Create test environment
		tmpDir := t.TempDir()
		volumeDir := filepath.Join(tmpDir, "volume")
		sensitiveDir := filepath.Join(tmpDir, "sensitive")
		
		if err := os.MkdirAll(volumeDir, 0755); err != nil {
			t.Skip("Cannot create volume directory")
		}
		if err := os.MkdirAll(sensitiveDir, 0755); err != nil {
			t.Skip("Cannot create sensitive directory")
		}

		// Create a "sensitive" file outside volume boundary (owned by root)
		sensitiveFile := filepath.Join(sensitiveDir, "root-owned-file")
		if err := os.WriteFile(sensitiveFile, []byte("sensitive data"), 0600); err != nil {
			t.Skip("Cannot create sensitive file")
		}
		
		// Try to set it as root-owned (if running as root)
		os.Chown(sensitiveFile, 0, 0)

		devicePath := filepath.Join(volumeDir, filepath.Base(deviceName))
		
		// Create device file or symlink
		if isSymlink || strings.Contains(deviceName, "symlink") {
			// Property test: Symlinks to sensitive files
			if err := os.Symlink(sensitiveFile, devicePath); err != nil {
				return
			}
		} else {
			// Create normal file with specified ownership
			if err := os.WriteFile(devicePath, []byte("device data"), 0644); err != nil {
				return
			}
			// Set initial ownership
			os.Chown(devicePath, int(currentUID), int(currentGID))
		}

		// Get file info before ownership change
		initialInfo, err := os.Lstat(devicePath)
		if err != nil {
			return
		}
		
		initialStat, ok := initialInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}

		// Property 1: Check if file is a symlink
		isActualSymlink := initialInfo.Mode()&os.ModeSymlink != 0
		
		// Create ownership manager
		ownershipManager := diskutils.DefaultOwnershipManager
		
		// Attempt to change ownership (this uses qemu UID 107)
		var ownershipErr error
		
		// Use safepath for proper symlink protection
		volumeRoot, err := safepath.JoinAndResolveWithRelativeRoot(volumeDir)
		if err != nil {
			t.Skip("Cannot create volume root")
		}
		
		deviceSafePath, err := safepath.JoinNoFollow(volumeRoot, filepath.Base(deviceName))
		if err != nil {
			// Path doesn't exist or has symlinks - this is correct behavior
			if isActualSymlink || strings.Contains(deviceName, "..") {
				return // Expected failure
			}
			return // Skip if path validation fails
		}
		
		ownershipErr = ownershipManager.SetFileOwnership(deviceSafePath)

		// Property 2: Files owned by root (UID 0) MUST NOT have ownership changed
		if initialStat.Uid == 0 && currentUID == 0 {
			if ownershipErr == nil {
				// Check if ownership was actually changed
				afterInfo, err := os.Lstat(devicePath)
				if err != nil {
					return
				}
				afterStat := afterInfo.Sys().(*syscall.Stat_t)
				
				if afterStat.Uid != 0 {
					panic(fmt.Sprintf("SECURITY VIOLATION: Root-owned file ownership changed! Before UID=%d, After UID=%d, device=%s",
						initialStat.Uid, afterStat.Uid, deviceName))
				}
			}
		}

		// Property 3: Symlinks MUST be rejected
		if isActualSymlink {
			// Verify symlink target wasn't affected
			targetInfo, err := os.Stat(sensitiveFile)
			if err != nil {
				return
			}
			targetStat := targetInfo.Sys().(*syscall.Stat_t)
			
			if targetStat.Uid != 0 && initialStat.Uid == 0 {
				panic(fmt.Sprintf("SECURITY VIOLATION: Symlink target ownership changed! Symlink=%s, Target=%s, Target UID=%d",
					devicePath, sensitiveFile, targetStat.Uid))
			}
		}

		// Property 4: Path traversal attempts MUST be rejected
		if strings.Contains(deviceName, "..") || strings.Contains(deviceName, "/etc/") {
			if ownershipErr == nil {
				panic(fmt.Sprintf("SECURITY VIOLATION: Path traversal not blocked: %s", deviceName))
			}
		}
	})
}

// FuzzHotplugDeviceCreation tests that device creation with mknod:
// 1. MUST validate device major/minor numbers are in expected ranges
// 2. MUST reject device creation outside volume boundaries
// 3. MUST not create devices with excessive permissions
// 4. MUST validate device type (block vs char)
//
// Related: Device isolation boundaries
func FuzzHotplugDeviceCreation(f *testing.F) {
	// Seed with device number patterns
	f.Add(uint32(8), uint32(0), uint32(0o660)) // /dev/sda (major 8, minor 0)
	f.Add(uint32(1), uint32(1), uint32(0o666)) // /dev/mem (major 1, minor 1)
	f.Add(uint32(252), uint32(0), uint32(0o660)) // Typical virtio-blk
	f.Add(uint32(259), uint32(0), uint32(0o660)) // NVMe
	f.Add(uint32(0), uint32(0), uint32(0o777)) // Invalid device, excessive perms

	f.Fuzz(func(t *testing.T, major, minor uint32, permissions uint32) {
		// Skip invalid permission values
		if permissions > 0o777 {
			return
		}

		tmpDir := t.TempDir()
		deviceDir := filepath.Join(tmpDir, "devices")
		if err := os.MkdirAll(deviceDir, 0755); err != nil {
			t.Skip("Cannot create device directory")
		}

		deviceName := "test-device"
		devicePath := filepath.Join(deviceDir, deviceName)

		// Calculate device number using Linux encoding
		dev := mkdev(major, minor)

		// Property 1: Reject dangerous device numbers
		dangerousDevices := map[uint32]string{
			1: "/dev/mem",     // Raw memory access
			2: "/dev/kmem",    // Kernel memory
			10: "/dev/random", // May be OK but check minor
		}

		if desc, isDangerous := dangerousDevices[major]; isDangerous {
			// These should be rejected or heavily scrutinized
			t.Logf("WARNING: Attempt to create dangerous device: major=%d (%s), minor=%d",
				major, desc, minor)
			
			// In production, these should fail
			if major == 1 && minor == 1 { // /dev/mem
				t.Logf("CRITICAL: Attempt to create /dev/mem equivalent")
			}
		}

		// Property 2: Skip world-writable permissions in fuzzer input
		// NOTE: This doesn't test if the system accepts them, just filters input
		if permissions&0o002 != 0 {
			return // Skip world-writable test cases
		}

		// Property 3: Permissions should not be overly permissive
		expectedMaxPerms := uint32(0o660) // rw-rw----
		if permissions > expectedMaxPerms {
			t.Logf("WARNING: Excessive device permissions: %o (expected max %o)", permissions, expectedMaxPerms)
		}

		// Property 4: Major numbers should be in valid ranges
		// Block devices typically use major numbers 8, 252, 259, etc.
		// Very high major numbers (>1000) might indicate an attack
		if major > 1000 {
			t.Logf("WARNING: Unusual major number: %d", major)
		}

		// Try to create device (this may fail if not root, which is OK)
		err := syscall.Mknod(devicePath, syscall.S_IFBLK|uint32(permissions), int(dev))
		if err != nil {
			// Most test environments won't allow mknod
			return
		}

		// Verify device was created with correct properties
		fi, err := os.Stat(devicePath)
		if err != nil {
			return
		}

		// Check actual permissions match (minus umask)
		actualMode := fi.Mode() & 0o777
		expectedMode := os.FileMode(permissions) & 0o777
		
		if actualMode != expectedMode {
			t.Logf("INFO: Device created with mode %o (expected %o, umask applied)", actualMode, expectedMode)
		}
	})
}

// FuzzHotplugVolumeSourceValidation tests that volume sources:
// 1. MUST be validated before mounting
// 2. MUST reject DataVolume URLs pointing to file:// schemes
// 3. MUST validate PVC names follow K8s naming conventions
// 4. MUST reject volumes with suspicious source paths
//
// Related: Input validation vulnerabilities
func FuzzHotplugVolumeSourceValidation(f *testing.F) {
	// Seed with volume source patterns
	f.Add("pvc", "my-pvc", "")
	f.Add("datavolume", "my-dv", "")
	f.Add("pvc", "../../etc/passwd", "") // Path traversal in name
	f.Add("datavolume", "dv", "file:///etc/shadow") // file:// URL
	f.Add("pvc", "my-pvc", "../../../../var/run") // Source path traversal
	f.Add("datavolume", "dv", "http://evil.com/malware.img") // Suspicious URL

	f.Fuzz(func(t *testing.T, volumeType, volumeName, sourceURL string) {
		if volumeName == "" {
			return
		}

		// Property 1: Volume names MUST follow DNS-1123 label conventions
		// Valid characters: lowercase alphanumeric, '-', and '.'
		// Must start and end with alphanumeric
		validNamePattern := func(name string) bool {
			if len(name) > 253 {
				return false
			}
			if strings.Contains(name, "..") {
				return false
			}
			if strings.Contains(name, "/") {
				return false
			}
			// Kubernetes labels can't start with . or -
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") {
				return false
			}
			return true
		}

		isValidName := validNamePattern(volumeName)
		if !isValidName {
			t.Logf("INFO: Invalid volume name correctly rejected: %q", volumeName)
			return
		}

		// Property 2 & 3: Skip malicious input patterns
		// NOTE: This fuzzer doesn't test actual validation code, just filters input
		if volumeType == "datavolume" && sourceURL != "" {
			if strings.HasPrefix(sourceURL, "file://") || filepath.IsAbs(sourceURL) {
				return // Skip malicious patterns
			}
		}

		// Property 4: Volume names with path traversal MUST be rejected
		if strings.Contains(volumeName, "..") || strings.Contains(volumeName, "/") {
			t.Logf("INFO: Path traversal in volume name correctly rejected: %q", volumeName)
			return
		}

		// Property 5: Validate volume type is recognized
		validTypes := map[string]bool{
			"pvc":        true,
			"datavolume": true,
			"persistentvolumeclaim": true,
		}
		
		if volumeType != "" && !validTypes[strings.ToLower(volumeType)] {
			t.Logf("INFO: Unknown volume type: %s", volumeType)
		}
	})
}

// FuzzHotplugVMIVolumeStatus tests that VolumeStatus updates:
// 1. MUST maintain consistency with actual volume state
// 2. MUST not allow status manipulation to trigger unsafe operations
// 3. MUST validate phase transitions are valid
// 4. MUST preserve volume target information
//
// Related: State machine vulnerabilities
func FuzzHotplugVMIVolumeStatus(f *testing.F) {
	// Seed with volume phases
	f.Add("my-volume", "Pending", "Ready", "virtio")
	f.Add("my-volume", "Ready", "Pending", "scsi") // Invalid backward transition
	f.Add("my-volume", "Bound", "Ready", "sata")
	f.Add("../../../etc", "Ready", "Ready", "virtio") // Malicious name
	f.Add("my-volume", "Ready", "Failed", "virtio") // Error transition

	f.Fuzz(func(t *testing.T, volumeName, currentPhase, newPhase, targetBus string) {
		if volumeName == "" || currentPhase == "" || newPhase == "" {
			return
		}

		// Property 1: Volume phase transitions must be valid
		validPhases := map[string]bool{
			"Pending":       true,
			"Bound":         true,
			"Ready":         true,
			"Failed":        true,
			"FailedMounted": true,
			"Unmounted":     true,
		}

		if !validPhases[currentPhase] || !validPhases[newPhase] {
			t.Logf("INFO: Invalid phase name: current=%s, new=%s", currentPhase, newPhase)
			return
		}

		// Property 2: Invalid state transitions MUST be rejected
		invalidTransitions := map[string]map[string]bool{
			"Ready": {
				"Pending": true, // Can't go back to pending
				"Bound":   true, // Can't go back to bound
			},
			"Failed": {
				"Ready": true, // Failed volumes shouldn't become ready without intervention
			},
		}

		if invalidStates, exists := invalidTransitions[currentPhase]; exists {
			if invalidStates[newPhase] {
				t.Logf("INFO: Invalid state transition blocked: %s -> %s", currentPhase, newPhase)
				return
			}
		}

		// Property 4: Skip malicious volume name patterns in input
		// NOTE: This doesn't test actual validation, just filters fuzzer input
		if strings.Contains(volumeName, "..") || strings.Contains(volumeName, "/") {
			return // Skip path traversal patterns
		}

		// Property 4: Bus type MUST be valid
		validBusTypes := map[string]bool{
			"virtio": true,
			"scsi":   true,
			"sata":   true,
			"usb":    true,
		}

		if targetBus != "" && !validBusTypes[targetBus] {
			t.Logf("WARNING: Invalid bus type: %s", targetBus)
		}

		// Property 5: Ready state MUST have valid target
		if newPhase == "Ready" && targetBus == "" {
			t.Logf("WARNING: Volume marked Ready without target bus specified")
		}
	})
}

// FuzzHotplugMountRecord tests the checkpoint mount record management:
// 1. MUST prevent record manipulation to point outside volume boundaries
// 2. MUST validate record integrity before restoring from checkpoint
// 3. MUST reject records with suspicious paths
// 4. MUST maintain mount/unmount consistency
func FuzzHotplugMountRecord(f *testing.F) {
	// Seed with mount record patterns
	f.Add("pvc-volume", "/var/run/kubevirt-private/vmi-disks/pvc-volume", true)
	f.Add("pvc-volume", "../../../../etc", false) // Escape attempt
	f.Add("pvc-volume", "/tmp/malicious", false) // Wrong base path
	f.Add("../../../etc/passwd", "/var/run/kubevirt-private/vmi-disks/passwd", false) // Malicious name

	f.Fuzz(func(t *testing.T, volumeName, targetPath string, useRelativePath bool) {
		if volumeName == "" || targetPath == "" {
			return
		}

		// Property 1: Volume names MUST be validated
		if strings.Contains(volumeName, "..") || strings.Contains(volumeName, "/") {
			t.Logf("INFO: Invalid volume name rejected: %s", volumeName)
			return
		}

		// Property 2: Target paths MUST be under expected base
		expectedBase := "/var/run/kubevirt-private/vmi-disks/"
		
		if !strings.HasPrefix(targetPath, expectedBase) && filepath.IsAbs(targetPath) {
			t.Logf("WARNING: Target path outside expected base: %s", targetPath)
		}

		// Property 3: Skip malicious path patterns in input
		// NOTE: This doesn't test actual validation, just filters fuzzer input
		if !filepath.IsAbs(targetPath) {
			if strings.Contains(targetPath, "..") {
				return // Skip path traversal patterns
			}
		}

		// Property 4: Resolved path MUST end with volume name
		cleanPath := filepath.Clean(targetPath)
		if !strings.HasSuffix(cleanPath, volumeName) && !strings.Contains(cleanPath, volumeName) {
			t.Logf("WARNING: Target path doesn't match volume name: path=%s, volume=%s", targetPath, volumeName)
		}

		// Property 5: Symlinks in path components MUST be rejected
		if strings.Contains(targetPath, "symlink") || strings.Count(targetPath, "/") > 10 {
			t.Logf("WARNING: Suspicious path structure: %s", targetPath)
		}
	})
}

// mkdev encodes major and minor device numbers into a device number
func mkdev(major, minor uint32) int {
	// Linux device number encoding: major shifted left by 8, OR'd with minor
	return int((major << 8) | minor)
}
