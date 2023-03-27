// Copyright 2023 the cncf-fuzzing authors
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

package verifier

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	notation "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	orasRegistry "oras.land/oras-go/v2/registry"
)

var (
	verificationLevels = map[int]string{
		0: "strict",
		1: "permissive",
		2: "audit",
	}
	defaultVerificationLevel = "audit"
	separators               = []string{".", "/", "-"}
	scopeChars               = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-_/.:[]@"
)

func createScope(ff *fuzz.ConsumeFuzzer) (string, error) {
	var b strings.Builder
	var noOfChars int
	noOfChars, err := ff.GetInt()
	if err != nil {
		return "domain.com/my/repository", nil
	}
	if noOfChars == 0 {
		noOfChars = 10
	}
	str, err := ff.GetStringFrom(scopeChars, noOfChars)
	if err != nil {
		return "domain.com/my/repository", nil
	}
	b.WriteString(str)
	if !strings.Contains(str, ".") {
		b.WriteString(".com/")

		noOfChars, err = ff.GetInt()
		if noOfChars == 0 {
			noOfChars = 10
		}
		repoStr1, err := ff.GetStringFrom(scopeChars, noOfChars)
		if err != nil {
			return "domain.com/my/repository", nil
		}
		b.WriteString(repoStr1)
		b.WriteString("/")

		noOfChars, err = ff.GetInt()
		if noOfChars == 0 {
			noOfChars = 10
		}
		repoStr2, err := ff.GetStringFrom(scopeChars, noOfChars)
		if err != nil {
			return "domain.com/my/repository", nil
		}
		b.WriteString(repoStr2)
	}

	return b.String(), nil

}

func createTrustPolicy(ff *fuzz.ConsumeFuzzer) (trustpolicy.TrustPolicy, error) {
	var name string
	var noOfChars int
	var (
		wg sync.WaitGroup
		m  sync.Mutex
	)
	noOfChars, err := ff.GetInt()
	if err != nil || noOfChars == 0 {
		noOfChars = 10
	}
	name, err = ff.GetStringFrom(scopeChars, noOfChars)
	if err != nil {
		return trustpolicy.TrustPolicy{}, err
	}
	registryScopes := make([]string, 0)
	// create trust stores according to the v2 specification
	noOfRegistryScopes, err := ff.GetInt()
	if err != nil {
		return trustpolicy.TrustPolicy{}, err
	}
	noOfRegistryScopes = noOfRegistryScopes % 20
	if noOfRegistryScopes == 0 {
		noOfRegistryScopes = 1
	}
	for i := 0; i < noOfRegistryScopes%20; i++ {
		wg.Add(1)
		scopeBytes, err := ff.GetBytes()
		if err != nil {
			return trustpolicy.TrustPolicy{}, err
		}
		ff1 := fuzz.NewConsumer(scopeBytes)
		go func(ff2 *fuzz.ConsumeFuzzer) {
			defer wg.Done()
			registryScope, err := createScope(ff2)
			if err != nil {
				return
			}
			m.Lock()
			registryScopes = append(registryScopes, registryScope)
			m.Unlock()
		}(ff1)
	}
	wg.Wait()

	if len(registryScopes) == 0 {
		return trustpolicy.TrustPolicy{}, fmt.Errorf("need at least one registryScope")
	}

	trustStores := make([]string, 0)
	var trustedIdentities []string
	trustedIdentities = make([]string, 0)

	veriLevel, err := ff.GetInt()
	if err != nil {
		return trustpolicy.TrustPolicy{}, err
	}

	verificationLevelName := verificationLevels[veriLevel%len(verificationLevels)]
	if verificationLevelName != "skip" {

		// create trust stores according to the v2 specification
		noOfTrustStores, err := ff.GetInt()
		if err != nil {
			return trustpolicy.TrustPolicy{}, err
		}
		noOfTrustStores = noOfTrustStores % 20
		if noOfTrustStores == 0 {
			noOfTrustStores = 1
		}
		for i := 0; i < noOfTrustStores%20; i++ {
			wg.Add(1)
			ff2Bytes, err := ff.GetBytes()
			if err != nil {
				return trustpolicy.TrustPolicy{}, err
			}
			ff2 := fuzz.NewConsumer(ff2Bytes)
			go func(ff *fuzz.ConsumeFuzzer) {
				defer wg.Done()
				var b strings.Builder
				addCA, err := ff.GetBool()
				if err != nil {
					return
				}

				trustStoreLength, err := ff.GetInt()
				if err != nil {
					return
				}
				trustStoreName, err := ff.GetStringFrom(scopeChars, trustStoreLength)
				if err != nil {
					return
				}
				if !file.IsValidFileName(trustStoreName) {
					return
				}

				if addCA {
					b.WriteString("ca")
				} else {
					b.WriteString("signingAuthority")
				}
				b.WriteString(":")
				b.WriteString(trustStoreName)
				m.Lock()
				trustStores = append(trustStores, b.String())
				m.Unlock()
			}(ff2)
		}
		wg.Wait()

		if len(trustStores) == 0 {
			return trustpolicy.TrustPolicy{}, fmt.Errorf("Could not create truststores")
		}

		// trusted identities
		noOfTrustedIdentities, err := ff.GetInt()
		if err != nil {
			return trustpolicy.TrustPolicy{}, err
		}
		noOfTrustedIdentities = noOfTrustedIdentities % 20
		if noOfTrustedIdentities == 0 {
			noOfTrustedIdentities = 1
		}
		for i := 0; i < noOfTrustStores%20; i++ {
			var b strings.Builder
			addX509Subject, err := ff.GetBool()
			if err != nil {
				break
			}

			var identityPrefix string
			if addX509Subject {
				identityPrefix = "x509.subject"
			} else {
				identityPrefix, err = ff.GetString()
				if err != nil {
					break
				}
			}
			b.WriteString(identityPrefix)
			b.WriteString(":")
			identityValue, err := ff.GetString()
			if err != nil {
				if len(trustedIdentities) == 0 {
					trustedIdentities = append(trustedIdentities, "x509.subject:C=US,ST=WA,O=MyOrg,CustomRDN=CustomValue")
				}
				break
			}
			if identityValue == "" {
				continue
			}
			b.WriteString(identityValue)
			trustedIdentities = append(trustedIdentities, b.String())
		}
		if len(trustStores) == 0 {
			return trustpolicy.TrustPolicy{}, fmt.Errorf("Invalid configurations")
		}
	}

	var sv *trustpolicy.SignatureVerification

	sv = &trustpolicy.SignatureVerification{}
	err = ff.GenerateStruct(sv)
	if err != nil || sv.VerificationLevel == trustpolicy.LevelSkip.Name {
		sv = &trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name}
	}
	sv.VerificationLevel = verificationLevelName
	return trustpolicy.TrustPolicy{
		Name:                  name,
		RegistryScopes:        registryScopes,
		SignatureVerification: *sv,
		TrustStores:           trustStores,
		TrustedIdentities:     trustedIdentities,
	}, nil
}

func createTrustPolicies(ff *fuzz.ConsumeFuzzer) ([]trustpolicy.TrustPolicy, error) {
	var policies []trustpolicy.TrustPolicy
	policies = make([]trustpolicy.TrustPolicy, 0)
	numberOfPolicies, err := ff.GetInt()
	if err != nil {
		return policies, err
	}
	numberOfPolicies = numberOfPolicies % 3
	if numberOfPolicies == 0 {
		numberOfPolicies = 1
	}
	var (
		m  sync.Mutex
		wg sync.WaitGroup
	)
	for i := 0; i < numberOfPolicies; i++ {
		policyBytes, err := ff.GetBytes()
		if err != nil {
			return policies, err
		}
		ff2 := fuzz.NewConsumer(policyBytes)
		wg.Add(1)
		go func(ff2 *fuzz.ConsumeFuzzer) {
			defer wg.Done()
			policy, err := createTrustPolicy(ff2)
			if err == nil {
				m.Lock()
				policies = append(policies, policy)
				m.Unlock()
			}
			return
		}(ff2)
	}
	wg.Wait()
	if len(policies) == 0 {
		return policies, fmt.Errorf("Did not create any policies")
	}
	return policies, nil
}

func createOptions(ff *fuzz.ConsumeFuzzer) (notation.RemoteVerifyOptions, error) {
	pluginConfig := make(map[string]string)
	err := ff.FuzzMap(&pluginConfig)
	if err != nil {
		return notation.RemoteVerifyOptions{}, err
	}
	maxSignatureAttempts, err := ff.GetInt()
	if err != nil {
		return notation.RemoteVerifyOptions{}, err
	}
	return notation.RemoteVerifyOptions{
		ArtifactReference:    "",
		PluginConfig:         pluginConfig,
		MaxSignatureAttempts: maxSignatureAttempts,
	}, nil
}

var (
	ts             truststore.X509TrustStore
	policyDocument = dummyPolicyDocument()
	vv             *verifier
	skv            *noSkipVerifier
	mockRepo       = mock.NewRepository()
	counter        = 0
)

type noSkipVerifier struct {
	trustPolicyDoc *trustpolicy.Document
	trustStore     truststore.X509TrustStore
	pluginManager  plugin.Manager
}

func (v *noSkipVerifier) Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts notation.VerifyOptions) (*notation.VerificationOutcome, error) {
	return vv.Verify(ctx, desc, signature, opts)
}

func init() {
	os.Mkdir("fuzz-dir", 0750)
	dir.UserConfigDir = "fuzz-dir"
	ts = truststore.NewX509TrustStore(dir.ConfigFS())
	vv = &verifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     ts,
		pluginManager:  mock.PluginManager{},
	}
	skv = &noSkipVerifier{
		trustPolicyDoc: &policyDocument,
		trustStore:     ts,
		pluginManager:  mock.PluginManager{},
	}
}

func FuzzVerify(f *testing.F) {
	f.Fuzz(func(t *testing.T, policyDocBytes []byte) {
		ff := fuzz.NewConsumer(policyDocBytes)
		artifactRef, err := ff.GetString()
		if err != nil {
			return
		}
		ref, err := orasRegistry.ParseReference(artifactRef)
		if err != nil || ref.Reference == "" {
			return
		}
		policies, err := createTrustPolicies(ff)
		if err != nil {
			t.Skip()
		}
		policiesLen := len(policies)
		if policiesLen == 0 {
			return
		}

		opts, err := createOptions(ff)
		if err != nil {
			t.Skip()
		}
		opts.ArtifactReference = artifactRef

		// MaxSignatureAttempts cannot be 0 or negative
		if opts.MaxSignatureAttempts == 0 {
			opts.MaxSignatureAttempts = 1
		}

		policyDoc := trustpolicy.Document{
			Version:       "1.0",
			TrustPolicies: policies,
		}
		err = policyDoc.Validate()
		if err != nil {
			t.Skip()
		}
		vv.trustPolicyDoc = &policyDoc
		skv.trustPolicyDoc = &policyDoc

		var err2 error
		_, _, err2 = notation.Verify(context.Background(), skv, mockRepo, opts)
		if err2 != nil {
			//fmt.Println("err2: ", err2)
		}
	})
}
