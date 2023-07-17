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
import java.io.IOException;
import org.keycloak.common.crypto.ECDSACryptoProvider;
import org.keycloak.crypto.def.BCECDSACryptoProvider;
import org.keycloak.crypto.elytron.ElytronECDSACryptoProvider;
import org.wildfly.security.asn1.ASN1Exception;

/**
 * This fuzzer targets the methods in different
 * ECDSA Crypto Provider implementation classes
 * in the crypto package.
 */
public class ECDSACryptoProviderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomly create an instance of ECDSACryptoProvider
      ECDSACryptoProvider provider = null;
      if (data.consumeBoolean()) {
        provider = new BCECDSACryptoProvider();
      } else {
        provider = new ElytronECDSACryptoProvider();
      }

      // Randomly call method from the ECDSACryptoProvider instance
      Integer length = data.consumeInt();
      byte[] bytes = data.consumeRemainingAsBytes();
      if (data.consumeBoolean()) {
        provider.concatenatedRSToASN1DER(bytes, length);
      } else {
        provider.asn1derToConcatenatedRS(bytes, length);
      }
    } catch (IOException | ASN1Exception e) {
      // Known exception
    }
  }
}
