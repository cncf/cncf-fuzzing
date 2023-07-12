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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.alg.DirectAlgorithmProvider;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.AesCbcHmacShaJWEEncryptionProvider;
import org.keycloak.jose.jwe.enc.AesGcmJWEEncryptionProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.util.TokenUtil;

/**
  This fuzzer targets the methods in JWKParser.
  It passes random string to the JWKParser object
  and call other methods that rely on the parsing
  result randomly.
  */
public class TokenUtilFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Set up a list of valid algorithm for the JWE object
      String[] alg = {
        JWEConstants.DIRECT, JWEConstants.A128KW, JWEConstants.RSA1_5,
        JWEConstants.RSA_OAEP, JWEConstants.RSA_OAEP_256
      };

      // Set up a list of valid encryption / compression
      // algorithm for the JWE object
      String[] enc = {
        JWEConstants.A128CBC_HS256, JWEConstants.A192CBC_HS384,
        JWEConstants.A256CBC_HS512, JWEConstants.A128GCM,
        JWEConstants.A192GCM, JWEConstants.A256GCM
      };

      Integer choice = data.consumeInt(1, 7);

      KeyGenerator generator = KeyGenerator.getInstance("AES");
      generator.init(128);
      Key aesKey = generator.generateKey();

      generator = KeyGenerator.getInstance("HmacSHA256");
      Key hmacKey = generator.generateKey();

      switch(choice) {
        case 1:
          TokenUtil.isOfflineToken(data.consumeRemainingAsString());
          break;
        case 2:
          TokenUtil.getRefreshToken(data.consumeRemainingAsBytes());
          break;
        case 3:
          TokenUtil.jweDirectEncode(aesKey, hmacKey, data.consumeRemainingAsBytes());
          break;
        case 4:
          TokenUtil.jweDirectVerifyAndDecode(aesKey, hmacKey, data.consumeRemainingAsString());
          break;
        case 5:
          TokenUtil.jweKeyEncryptionVerifyAndDecode(aesKey, data.consumeRemainingAsString());
          break;
        case 6:
        case 7:
          String algAlgorithm = data.pickValue(alg);
          String encAlgorithm = data.pickValue(enc);
          String kid = data.consumeString(10);
          JWEAlgorithmProvider jweAlgorithmProvider = new DirectAlgorithmProvider();
          JWEEncryptionProvider jweEncryptionProvider;
          if (data.consumeBoolean()) {
            jweEncryptionProvider = new AesCbcHmacShaJWEEncryptionProvider(data.pickValue(enc));
          } else {
            jweEncryptionProvider = new AesGcmJWEEncryptionProvider(data.pickValue(enc));
          }

          if (choice == 6) {
            TokenUtil.jweKeyEncryptionEncode(
                aesKey, data.consumeRemainingAsBytes(), algAlgorithm, encAlgorithm,
                kid, jweAlgorithmProvider, jweEncryptionProvider
            );
          } else {
            TokenUtil.jweKeyEncryptionVerifyAndDecode(
                aesKey, data.consumeRemainingAsString(),
                jweAlgorithmProvider, jweEncryptionProvider
            );
          }
          break;
      }
    } catch (JWSInputException | JWEException | NoSuchAlgorithmException e) {
      // Known exception
    }
  }
}
