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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.JsonWebToken;

public class TokenVerifierFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      TokenVerifier verifier = TokenVerifier.create(data.consumeRemainingAsString(), JsonWebToken.class);
      if ((verifier.getHeader() == null) || (verifier.getHeader().getAlgorithm() == null)) {
        // Malformed JsonWebToken, skipping to next iteration.
        return;
      }
      verifier.verify();
    } catch (VerificationException e) {
      // Known exception
    }
  }
}
