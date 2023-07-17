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
import javax.crypto.KeyGenerator;
import org.keycloak.crypto.def.AesKeyWrapAlgorithmProvider;
import org.keycloak.crypto.def.DefaultRsaKeyEncryption256JWEAlgorithmProvider;
import org.keycloak.crypto.elytron.ElytronRsaKeyEncryption256JWEAlgorithmProvider;
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
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Set up a list of valid encryption algorithm for the JWE object
      String[] enc = {JWEConstants.A128GCM, JWEConstants.A192GCM, JWEConstants.A256GCM};

      // Initialize the base object for key management and generation
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);

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
          algorithmProvider = new AesKeyWrapAlgorithmProvider();
          break;
        case 2:
          keyGenerator.init(256);
          encryptionKey = keyGenerator.generateKey();
          decryptionKey = encryptionKey;
          algorithmProvider = new org.keycloak.crypto.elytron.AesKeyWrapAlgorithmProvider();
          break;
        case 3:
          keyPair = generator.generateKeyPair();
          encryptionKey = keyPair.getPublic();
          decryptionKey = keyPair.getPrivate();
          algorithmProvider = new DefaultRsaKeyEncryption256JWEAlgorithmProvider("RSA");
          break;
        case 4:
          keyPair = generator.generateKeyPair();
          encryptionKey = keyPair.getPublic();
          decryptionKey = keyPair.getPrivate();
          algorithmProvider = new ElytronRsaKeyEncryption256JWEAlgorithmProvider("RSA");
          break;
      }

      // Randomly call method from the JWE algorithm provider instance
      if (data.consumeBoolean()) {
        JWEEncryptionProvider provider = new AesGcmJWEEncryptionProvider(data.pickValue(enc));
        JWEKeyStorage storage = new JWEKeyStorage();
        storage.setEncryptionProvider(provider);
        storage.setEncryptionKey(encryptionKey);
        storage.setDecryptionKey(decryptionKey);

        algorithmProvider.encodeCek(provider, storage, encryptionKey);
      } else {
        algorithmProvider.decodeCek(data.consumeRemainingAsBytes(), decryptionKey);
      }
    } catch (Exception e) {
      // Known exception
    }
  }
}
