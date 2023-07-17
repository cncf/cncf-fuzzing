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
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.keycloak.common.crypto.CertificateUtilsProvider;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.crypto.def.BCCertificateUtilsProvider;
import org.keycloak.crypto.elytron.ElytronCertificateUtils;

/**
 * This fuzzer targets the methods in different
 * Certificate Utils Provider implementation classes
 * in the crypto package.
 */
public class CertificateUtilsProviderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Initialise base certificate related object
    CertificateUtilsProvider provider = null;
    X509Certificate cert = null;
    KeyPair keyPair = null;

    try {
      // Randomly create a certificate utils provider instance
      if (data.consumeBoolean()) {
        provider = new BCCertificateUtilsProvider();
      } else {
        provider = new ElytronCertificateUtils();
      }

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      // Randomly choose which method to invoke
      Integer choice = data.consumeInt(1, 4);
      switch (choice) {
        case 1:
          cert = (X509Certificate) cf.generateCertificate(
              new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          provider.generateV3Certificate(
              keyPair, keyPair.getPrivate(), cert, data.consumeRemainingAsString());
          break;
        case 2:
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          provider.generateV1SelfSignedCertificate(keyPair, data.consumeRemainingAsString());
          break;
        case 3:
          cert = (X509Certificate) cf.generateCertificate(
              new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          provider.getCertificatePolicyList(cert);
          break;
        case 4:
          cert = (X509Certificate) cf.generateCertificate(
              new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          provider.getCRLDistributionPoints(cert);
          break;
        case 5:
          keyPair = KeyUtils.generateRsaKeyPair(2048);
          Date startDate = new Date(data.consumeLong());
          Date expiryDate = new Date(data.consumeLong());
          provider.createServicesTestCertificate(data.consumeString(data.remainingBytes() / 2),
              startDate, expiryDate, keyPair, data.consumeRemainingAsString());
          break;
      }
    } catch (Exception e) {
      // Known exception
    }
  }
}
