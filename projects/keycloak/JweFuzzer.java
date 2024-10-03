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
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.HexFormat;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.enc.AesCbcHmacShaJWEEncryptionProvider;
import org.keycloak.jose.jwe.enc.AesGcmJWEEncryptionProvider;

/**
 * This fuzzer targets the encodeJwe method of the JWE class. It creates and initialize a JWE object
 * with random string or JWEHeader instance for further encoding process using the stored JWEHeader
 * object.
 */
public class JweFuzzer {
  // Throw other unexpected exceptions that are not caught.
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      // Determine how to create and initialize the JWE object
      Boolean choice = data.consumeBoolean();

      // Set up a list of valid algorithm for the JWE object
      String[] algs = {
        JWEConstants.DIRECT,
        JWEConstants.A128KW,
        JWEConstants.RSA1_5,
        JWEConstants.RSA_OAEP,
        JWEConstants.RSA_OAEP_256
      };

      // Set up a list of valid encryption / compression
      // algorithm for the JWE object
      String[] encs = {
        JWEConstants.A128CBC_HS256,
        JWEConstants.A192CBC_HS384,
        JWEConstants.A256CBC_HS512,
        JWEConstants.A128GCM,
        JWEConstants.A192GCM,
        JWEConstants.A256GCM
      };

      // Pick JWE object algorithms and encryption algorithms
      String alg = data.pickValue(algs);
      String enc = data.pickValue(encs);

      // Create JweKeyStorage
      byte[] keyBytes = data.consumeBytes(32);
      if (keyBytes.length == 0) {
        // If there is no more bytes from FuzzedDataProvider, use default key byte.
        keyBytes = HexFormat.of().parseHex("0123456789abcdef0123456789abcdef");
      }
      Key key = KeyUtils.loadSecretKey(keyBytes, "HmacSHA256");
      JWEKeyStorage keyStorage = new JWEKeyStorage();
      keyStorage.setEncryptionKey(key);
      keyStorage.setDecryptionKey(key);

      // Creates and initializes a JWEHeader object with random
      // pick of algorithms and encryption / compression algorithms
      JWEHeader header = new JWEHeader(alg, enc, enc);
      JWE jwe = null;

      if (choice) {
        // Creates and initializes a JWE object with random
        // JWEHeader string
        jwe = new JWE(data.consumeRemainingAsString());
      } else {
        // Creates and initializes a JWE object with the
        // JWEHeader object created above
        jwe = new JWE();
        jwe.header(header);
      }

      // Call the encodeJwe method which performs some
      // operations depennding on its JWEHeader configurations
      jwe.encodeJwe();

      // Creates and initializes JWEEncrpytionProvider objects
      AesCbcHmacShaJWEEncryptionProvider achsjeProvider =
          new AesCbcHmacShaJWEEncryptionProvider(enc);
      AesGcmJWEEncryptionProvider agjeProvider = new AesGcmJWEEncryptionProvider(enc);

      // Call the encodeJwe methods from JWEEncryptionProvider objects
      achsjeProvider.encodeJwe(jwe);
      agjeProvider.encodeJwe(jwe);

      // Call the verifyAndDecodeJwe methods from JWEEncryptionProvider objects
      achsjeProvider.verifyAndDecodeJwe(jwe);
      agjeProvider.verifyAndDecodeJwe(jwe);

      // Call the serializeCEK methods from JWEEncryptionProvider objects
      achsjeProvider.serializeCEK(keyStorage);
      agjeProvider.serializeCEK(keyStorage);

      // Call the deserializeCEK methods from JWEEncryptionProvider objects
      achsjeProvider.deserializeCEK(keyStorage);
      agjeProvider.deserializeCEK(keyStorage);
    } catch (JWEException | IOException | GeneralSecurityException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
