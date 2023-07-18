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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.keycloak.crypto.def.AesKeyWrapAlgorithmProvider;
import org.keycloak.crypto.def.DefaultRsaKeyEncryption256JWEAlgorithmProvider;
import org.keycloak.crypto.elytron.ElytronRsaKeyEncryption256JWEAlgorithmProvider;
import org.keycloak.crypto.fips.FIPSAesKeyWrapAlgorithmProvider;
import org.keycloak.crypto.fips.FIPSRsaKeyEncryptionJWEAlgorithmProvider;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.AesGcmJWEEncryptionProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;

/**
 * This fuzzer targets the methods in different
 * JweAlgorithm Provider implementation classes
 * in the crypto package.
 */
public class JweAlgorithmProviderFuzzer {
  // Set up a list of valid encryption algorithm for the JWE object
  private static final String[] enc = {
      JWEConstants.A128GCM, JWEConstants.A192GCM, JWEConstants.A256GCM};

  private static KeyGenerator keyGenerator;
  private static KeyPairGenerator generator;
  private static AesKeyWrapAlgorithmProvider akwaProvider;
  private static org.keycloak.crypto.elytron.AesKeyWrapAlgorithmProvider eakwaProvider;
  private static FIPSAesKeyWrapAlgorithmProvider fakwaProvider;
  private static DefaultRsaKeyEncryption256JWEAlgorithmProvider drkeaProvider;
  private static ElytronRsaKeyEncryption256JWEAlgorithmProvider erkeaProvider;
  private static FIPSRsaKeyEncryptionJWEAlgorithmProvider frkeaProvider;

  public static void fuzzerInitialize() {
    try {
      // Initialize the base object for key management and generation
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);

      // Initialize providers
      akwaProvider = new AesKeyWrapAlgorithmProvider();
      eakwaProvider = new org.keycloak.crypto.elytron.AesKeyWrapAlgorithmProvider();
      fakwaProvider = new FIPSAesKeyWrapAlgorithmProvider();
      drkeaProvider = new DefaultRsaKeyEncryption256JWEAlgorithmProvider("RSA");
      erkeaProvider = new ElytronRsaKeyEncryption256JWEAlgorithmProvider("RSA");
      frkeaProvider = new FIPSRsaKeyEncryptionJWEAlgorithmProvider(null);
    } catch (NoSuchAlgorithmException e) {
      // Known exception
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      JWEAlgorithmProvider algorithmProvider = null;
      KeyPair keyPair = null;
      Key encryptionKey = null;
      Key decryptionKey = null;

      // Randomly create an JWE Algorithm Provider instance
      // from different implementation
      switch (data.consumeInt(1, 6)) {
        case 1:
          keyGenerator.init(256);
          encryptionKey = keyGenerator.generateKey();
          decryptionKey = encryptionKey;
          algorithmProvider = akwaProvider;
          break;
        case 2:
          keyGenerator.init(256);
          encryptionKey = keyGenerator.generateKey();
          decryptionKey = encryptionKey;
          algorithmProvider = eakwaProvider;
        case 3:
          keyGenerator.init(256);
          encryptionKey = keyGenerator.generateKey();
          decryptionKey = encryptionKey;
          algorithmProvider = fakwaProvider;
          break;
        case 4:
          keyPair = generator.generateKeyPair();
          encryptionKey = keyPair.getPublic();
          decryptionKey = keyPair.getPrivate();
          algorithmProvider = drkeaProvider;
          break;
        case 5:
          keyPair = generator.generateKeyPair();
          encryptionKey = keyPair.getPublic();
          decryptionKey = keyPair.getPrivate();
          algorithmProvider = erkeaProvider;
          break;
        case 6:
          keyPair = generator.generateKeyPair();
          encryptionKey = keyPair.getPublic();
          decryptionKey = keyPair.getPrivate();
          algorithmProvider = frkeaProvider;
          break;
      }

      // Randomly choose to encode or decode with the JWE Algorithm provider instance
      if (data.consumeBoolean()) {
        JWEEncryptionProvider provider =
            new AesGcmJWEEncryptionProvider(data.pickValue(JweAlgorithmProviderFuzzer.enc));
        JWEKeyStorage storage = new JWEKeyStorage();
        storage.setEncryptionProvider(provider);
        storage.setEncryptionKey(encryptionKey);
        storage.setDecryptionKey(decryptionKey);

        algorithmProvider.encodeCek(provider, storage, encryptionKey);
      } else {
        algorithmProvider.decodeCek(data.consumeRemainingAsBytes(), decryptionKey);
      }
    } catch (Exception e) {
      // Known exception thrown directly from the encode or decode method.
    }
  }
}
