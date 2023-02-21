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
	"reflect"
	"regexp"
	"strings"
	"testing"

	notation "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/file"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	verificationLevels = map[int]string{
		0: "strict",
		1: "permissive",
		2: "audit",
		3: "skip",
	}
	defaultVerificationLevel = "audit"
	separators               = []string{".", "/", "-"}
	scopeChars               = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-_/.:[]@"
)

func createScope(ff *fuzz.ConsumeFuzzer) (string, error) {
	var b strings.Builder
	var noOfChars int
	noOfChars, err := ff.GetInt()
	if noOfChars == 0 {
		noOfChars = 10
	}
	if err != nil {
		return "domain.com/my/repository", err
	}
	str, err := ff.GetStringFrom(scopeChars, noOfChars)
	if err != nil {
		return "domain.com/my/repository", err
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
			return "domain.com/my/repository", err
		}
		b.WriteString(repoStr1)
		b.WriteString("/")

		noOfChars, err = ff.GetInt()
		if noOfChars == 0 {
			noOfChars = 10
		}
		repoStr2, err := ff.GetStringFrom(scopeChars, noOfChars)
		if err != nil {
			return "domain.com/my/repository", err
		}
		b.WriteString(repoStr2)
	}

	return b.String(), nil

}

func validateRegistryScopeFormat(scope string) error {
	// Domain and Repository regexes are adapted from distribution implementation
	// https://github.com/distribution/distribution/blob/main/reference/regexp.go#L31
	domainRegexp := regexp.MustCompile(`^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?$`)
	repositoryRegexp := regexp.MustCompile(`^[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?$`)
	errorMessage := "registry scope %q is not valid, make sure it is the fully qualified registry URL without the scheme/protocol. e.g domain.com/my/repository"
	domain, repository, found := strings.Cut(scope, "/")
	if !found {
		return fmt.Errorf(errorMessage, scope)
	}

	if domain == "" || repository == "" || !domainRegexp.MatchString(domain) || !repositoryRegexp.MatchString(repository) {
		return fmt.Errorf(errorMessage, scope)
	}

	// No errors
	return nil
}

func createTrustPolicy(ff *fuzz.ConsumeFuzzer) (trustpolicy.TrustPolicy, error) {
	var name string
	var noOfChars int
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
		registryScope, err := createScope(ff)
		if err != nil {
			return trustpolicy.TrustPolicy{}, err
		}
		err = validateRegistryScopeFormat(registryScope)
		if err != nil {
			return trustpolicy.TrustPolicy{}, err
		}

		registryScopes = append(registryScopes, registryScope)
	}

	if len(registryScopes) == 0 {
		return trustpolicy.TrustPolicy{}, fmt.Errorf("need at least one registryScope")
	}

	trustStores := make([]string, 0)
	trustedIdentities := make([]string, 0)

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
			var b strings.Builder
			addCA, err := ff.GetBool()
			if err != nil {
				break
			}

			trustStoreLength, err := ff.GetInt()
			if err != nil {
				break
			}
			trustStoreName, err := ff.GetStringFrom(scopeChars, trustStoreLength)
			if err != nil {
				break
			}
			if !file.IsValidFileName(trustStoreName) {
				continue
			}

			if addCA {
				b.WriteString("ca")
			} else {
				b.WriteString("signingAuthority")
			}
			b.WriteString(":")
			b.WriteString(trustStoreName)
			trustStores = append(trustStores, b.String())
		}

		if len(trustStores) < 3 {
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
				break
			}
			if identityValue == "" {
				continue
			}
			b.WriteString(identityValue)
			trustedIdentities = append(trustedIdentities, b.String())
		}
		if len(trustStores) < 2 || len(trustedIdentities) < 2 {
			return trustpolicy.TrustPolicy{}, fmt.Errorf("Invalid configurations")
		}
	}

	sv := &trustpolicy.SignatureVerification{}
	err = ff.GenerateStruct(sv)
	if err != nil {
		return trustpolicy.TrustPolicy{}, err
	}
	//fmt.Println("here3")
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
	policies := make([]trustpolicy.TrustPolicy, 0)
	numberOfPolicies, err := ff.GetInt()
	if err != nil {
		return policies, err
	}
	numberOfPolicies = numberOfPolicies % 10
	if numberOfPolicies == 0 {
		numberOfPolicies = 1
	}
	for i := 0; i < numberOfPolicies; i++ {
		policy, err := createTrustPolicy(ff)
		if err != nil {
			if len(policies) > 1 {
				return policies, nil
			} else {
				return policies, err
			}
		}
		policies = append(policies, policy)
	}
	if len(policies) == 0 {
		return policies, fmt.Errorf("Did not create any policies")
	}
	return policies, nil
}

func createOptions(ff *fuzz.ConsumeFuzzer) (notation.RemoteVerifyOptions, error) {
	var scope string
	var i int
	scope, err := createScope(ff)
	if err != nil {
		return notation.RemoteVerifyOptions{}, err
	}

	i = strings.LastIndex(scope, "@")
	if i < 0 {
		var b strings.Builder
		b.WriteString(scope)
		b.WriteString("@")
		noOfChars, err := ff.GetInt()
		if err != nil || noOfChars == 0 {
			noOfChars = 10
		}
		name2, err := ff.GetStringFrom(scopeChars, noOfChars)
		if err != nil {
			return notation.RemoteVerifyOptions{}, err
		}
		b.WriteString(name2)
		scope = b.String()
		i = strings.LastIndex(scope, "@")
	}

	artifactPath := scope[:i]
	err = validateRegistryScopeFormat(artifactPath)
	if err != nil {
		return notation.RemoteVerifyOptions{}, err
	}

	pluginConfig := make(map[string]string)
	err = ff.FuzzMap(&pluginConfig)
	if err != nil {
		return notation.RemoteVerifyOptions{}, err
	}
	maxSignatureAttempts, err := ff.GetInt()
	if err != nil {
		return notation.RemoteVerifyOptions{}, err
	}
	return notation.RemoteVerifyOptions{
		ArtifactReference:    scope,
		PluginConfig:         pluginConfig,
		MaxSignatureAttempts: maxSignatureAttempts,
	}, nil
}

func FuzzVerify(f *testing.F) {
	f.Fuzz(func(t *testing.T, policyDocBytes []byte) {
		ff := fuzz.NewConsumer(policyDocBytes)
		policies, err := createTrustPolicies(ff)
		if err != nil {
			t.Skip()
		}
		policyDoc := trustpolicy.Document{
			Version:       "1.0",
			TrustPolicies: policies,
		}

		err = policyDoc.Validate()
		if err != nil {
			t.Skip()
		}

		opts, err := createOptions(ff)
		if err != nil {
			t.Skip()
		}

		td := t.TempDir()
		dir.UserConfigDir = td

		v, err := New(&policyDoc, truststore.NewX509TrustStore(dir.ConfigFS()), mock.PluginManager{})
		if err != nil {
			t.Skip()
		}

		trustPolicy, err := policyDoc.GetApplicableTrustPolicy(opts.ArtifactReference)
		if err != nil {
			t.Skip()
		}
		verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()
		if reflect.DeepEqual(verificationLevel, trustpolicy.LevelSkip) {
			_, _, _ = notation.Verify(context.Background(), v, nil, opts)
		} else {
			_, _, _ = notation.Verify(context.Background(), v, mock.NewRepository(), opts)
		}
	})
}
