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
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.JWEHeader;

public class JweFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Boolean choice = data.consumeBoolean();

      String[] alg = {
        JWEConstants.DIRECT, JWEConstants.A128KW, JWEConstants.RSA1_5,
        JWEConstants.RSA_OAEP, JWEConstants.RSA_OAEP_256
      };

      String[] enc = {
        JWEConstants.A128CBC_HS256, JWEConstants.A192CBC_HS384,
        JWEConstants.A256CBC_HS512, JWEConstants.A128GCM,
        JWEConstants.A192GCM, JWEConstants.A256GCM
      };

      JWEHeader header = new JWEHeader(data.pickValue(alg), data.pickValue(enc), data.pickValue(enc));
      JWE jwe;

      if (choice) {
        jwe = new JWE(data.consumeRemainingAsString());
      } else {
        jwe = new JWE();
        jwe.header(header);
      }

      jwe.encodeJwe();
    } catch (RuntimeException | JWEException e) {
      // Known exception
    }
  }
}
