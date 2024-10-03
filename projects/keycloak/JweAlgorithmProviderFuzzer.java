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
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import org.bouncycastle.crypto.CryptoException;
import org.keycloak.crypto.def.AesKeyWrapAlgorithmProvider;
import org.keycloak.crypto.def.BCEcdhEsAlgorithmProvider;
import org.keycloak.crypto.def.DefaultRsaKeyEncryption256JWEAlgorithmProvider;
import org.keycloak.crypto.elytron.ElytronEcdhEsAlgorithmProvider;
import org.keycloak.crypto.elytron.ElytronRsaKeyEncryption256JWEAlgorithmProvider;
import org.keycloak.crypto.fips.BCFIPSEcdhEsAlgorithmProvider;
import org.keycloak.crypto.fips.FIPSAesKeyWrapAlgorithmProvider;
import org.keycloak.crypto.fips.FIPSRsaKeyEncryptionJWEAlgorithmProvider;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.alg.DirectAlgorithmProvider;
import org.keycloak.jose.jwe.enc.AesGcmJWEEncryptionProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;

/**
 * This fuzzer targets the encodeCek and decodeCek methods of different JweAlgorithm Provider
 * implementation classes in the crypto package.
 *
 * The fuzzer randomly selects a provider in each iteration and either encodes or decodes a value
 * specified by the fuzzer.
 */
public class JweAlgorithmProviderFuzzer {
  // Set up a list of valid encryption algorithm for the JWE object
  private static final String[] enc = {
    JWEConstants.A128GCM, JWEConstants.A192GCM, JWEConstants.A256GCM,
    JWEConstants.A128CBC_HS256, JWEConstants.A192CBC_HS384,
    JWEConstants.A256CBC_HS512
  };

  private static final String[] alg = {
    JWEConstants.DIRECT, JWEConstants.A128KW, JWEConstants.RSA1_5,
    JWEConstants.RSA_OAEP, JWEConstants.RSA_OAEP_256, JWEConstants.ECDH_ES,
    JWEConstants.ECDH_ES_A128KW, JWEConstants.ECDH_ES_A192KW,
    JWEConstants.ECDH_ES_A256KW
  };

  private static Key encryptionKey;
  private static Key decryptionKey;
  private static Key key;

  public static void fuzzerInitialize() {
    try {
      // Initialize the base object for key management and generation
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(256);
      key = keyGenerator.generateKey();

      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair keyPair = generator.generateKeyPair();
      encryptionKey = keyPair.getPublic();
      decryptionKey = keyPair.getPrivate();
    } catch (NoSuchAlgorithmException e) {
      // Known exception
    }
  }

  // TEMPORARY DISABLE FIPS CLASSES, TODO: HANDLES FIPS LATER
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      JWEAlgorithmProvider algorithmProvider = null;

      // Randomly create an JWE Algorithm Provider instance
      switch (data.consumeInt(1, 8)) {
        case 1:
          encryptionKey = key;
          decryptionKey = key;
          algorithmProvider = new DirectAlgorithmProvider();
          break;
        case 2:
          encryptionKey = key;
          decryptionKey = key;
          algorithmProvider = new AesKeyWrapAlgorithmProvider();
          break;
        case 3:
          encryptionKey = key;
          decryptionKey = key;
          algorithmProvider = new org.keycloak.crypto.elytron.AesKeyWrapAlgorithmProvider();
          break;
        case 4:
//          encryptionKey = key;
//          decryptionKey = key;
//          algorithmProvider = new FIPSAesKeyWrapAlgorithmProvider();
//        case 5:
          algorithmProvider = new DefaultRsaKeyEncryption256JWEAlgorithmProvider("RSA");
          break;
        case 5:
          algorithmProvider = new ElytronRsaKeyEncryption256JWEAlgorithmProvider("RSA");
          break;
        case 6:
          Key tempKey = decryptionKey;
          decryptionKey = encryptionKey;
          encryptionKey = tempKey;
          algorithmProvider = new BCEcdhEsAlgorithmProvider();
          break;
        case 7:
          algorithmProvider = new BCFIPSEcdhEsAlgorithmProvider();
          break;
        case 8:
          algorithmProvider = new ElytronEcdhEsAlgorithmProvider();
          break;
//        case 10:
//          algorithmProvider = new FIPSRsaKeyEncryptionJWEAlgorithmProvider(null);
      }

      // Generate JWEEncryptionProvider object
      JWEEncryptionProvider provider =
          new AesGcmJWEEncryptionProvider(data.pickValue(JweAlgorithmProviderFuzzer.enc));

      // Generate JWEHeader object
      JWEHeader header = new JWEHeader(
          data.pickValue(JweAlgorithmProviderFuzzer.alg),
          data.pickValue(JweAlgorithmProviderFuzzer.enc),
          null
      );

      // Randomly choose to encode or decode with the JWE Algorithm provider instance
      if (data.consumeBoolean()) {
        JWEKeyStorage storage = new JWEKeyStorage();
        storage.setEncryptionProvider(provider);
        storage.setEncryptionKey(encryptionKey);
        storage.setDecryptionKey(decryptionKey);

        algorithmProvider.encodeCek(provider, storage, encryptionKey, header.toBuilder());
      } else {
        algorithmProvider.decodeCek(data.consumeRemainingAsBytes(), decryptionKey, header, provider);
      }
    } catch (NoSuchMethodError | AssertionError e) {
      // Known error
    } catch (CryptoException | GeneralSecurityException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
