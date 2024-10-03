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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.DerUtils;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.common.util.PemUtils;

/**
 * This fuzzer targets the methods in different crypto related util classes in the common package.
 */
public class CommonCryptoUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    X509Certificate cert = null;
    KeyPair keyPair = null;

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      // Randomly choose which utils method to invoke
      Integer choice = data.consumeInt(1, 22);
      switch (choice) {
        case 1:
          cert =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(data.consumeBytes(data.consumeInt(0, 10000))));
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          CertificateUtils.generateV3Certificate(
              keyPair, keyPair.getPrivate(), cert, data.consumeRemainingAsString());
          break;
        case 2:
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          CertificateUtils.generateV1SelfSignedCertificate(
              keyPair, data.consumeRemainingAsString());
          break;
        case 3:
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          BigInteger serial = BigInteger.valueOf(data.consumeLong());
          CertificateUtils.generateV1SelfSignedCertificate(
              keyPair, data.consumeRemainingAsString(), serial);
          break;
        case 4:
          DerUtils.decodePrivateKey(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        case 5:
          DerUtils.decodePrivateKey(data.consumeRemainingAsBytes());
          break;
        case 6:
          DerUtils.decodePublicKey(
              data.consumeBytes(data.consumeInt(0, 10000)), data.consumeRemainingAsString());
          break;
        case 7:
          DerUtils.decodeCertificate(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        case 8:
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          KeyUtils.createKeyId(keyPair.getPrivate());
          break;
        case 9:
          KeystoreUtil.loadKeyStore(
              data.consumeString(data.consumeInt(0, 10000)), data.consumeRemainingAsString());
          break;
        case 10:
          KeystoreUtil.loadKeyPairFromKeystore(
              data.consumeString(data.consumeInt(0, 10000)),
              data.consumeString(data.consumeInt(0, 10000)),
              data.consumeString(data.consumeInt(0, 10000)),
              data.consumeString(data.consumeInt(0, 10000)),
              data.pickValue(EnumSet.allOf(KeystoreUtil.KeystoreFormat.class)));
          break;
        case 11:
          KeystoreUtil.getKeystoreType(
              data.consumeString(data.consumeInt(0, 10000)),
              data.consumeString(data.consumeInt(0, 10000)),
              data.consumeRemainingAsString());
          break;
        case 12:
          PemUtils.decodeCertificate(data.consumeRemainingAsString());
          break;
        case 13:
          PemUtils.decodePublicKey(data.consumeRemainingAsString());
          break;
        case 14:
          PemUtils.decodePublicKey(
              data.consumeString(data.consumeInt(0, 10000)), data.consumeRemainingAsString());
          break;
        case 15:
          PemUtils.decodePrivateKey(data.consumeRemainingAsString());
          break;
        case 16:
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          PemUtils.encodeKey(keyPair.getPrivate());
          break;
        case 17:
          cert =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(data.consumeBytes(data.consumeInt(0, 10000))));
          PemUtils.encodeCertificate(cert);
          break;
        case 18:
          PemUtils.pemToDer(data.consumeRemainingAsString());
          break;
        case 19:
          PemUtils.removeBeginEnd(data.consumeRemainingAsString());
          break;
        case 20:
          PemUtils.addPrivateKeyBeginEnd(data.consumeRemainingAsString());
          break;
        case 21:
          PemUtils.addRsaPrivateKeyBeginEnd(data.consumeRemainingAsString());
          break;
        case 22:
          String encoding = data.consumeString(data.consumeInt(0, 10000));
          String[] chain = {data.consumeRemainingAsString()};
          PemUtils.generateThumbprint(chain, encoding);
          break;
      }
    } catch (GeneralSecurityException | RuntimeException | IOException e) {
      // Known exception
    }
  }
}
