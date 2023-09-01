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
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.keycloak.common.crypto.CertificateUtilsProvider;
import org.keycloak.common.crypto.PemUtilsProvider;
import org.keycloak.common.crypto.UserIdentityExtractorProvider;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemException;
import org.keycloak.crypto.def.DefaultCryptoProvider;

/** This fuzzer targets the methods in different crypto provider. */
public class CryptoProviderFuzzer {
  private static CertificateFactory cf;
  private static DefaultCryptoProvider cryptoProvider;

  public static void fuzzerInitialize() throws GeneralSecurityException {
      cf = CertificateFactory.getInstance("X.509");
      cryptoProvider = new DefaultCryptoProvider();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    X509Certificate cert = null;
    KeyPair keyPair = null;

    try {
      // Randomly choose a crypto provider instance
      Integer choice = data.consumeInt(1, 4);
      switch (choice) {
        case 1:
          // CertificateUtilsProvider
          CertificateUtilsProvider certificateUtilsProvider = cryptoProvider.getCertificateUtils();
          cert =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          keyPair = KeyUtils.generateRsaKeyPair(2048);

          // Random choose method target for CertificateUtilsProvider
          switch (data.consumeInt(1, 6)) {
            case 1:
              certificateUtilsProvider.generateV3Certificate(
                  keyPair, keyPair.getPrivate(), cert, data.consumeRemainingAsString());
              break;
            case 2:
              certificateUtilsProvider.generateV1SelfSignedCertificate(
                  keyPair, data.consumeRemainingAsString());
              break;
            case 3:
              BigInteger serial = BigInteger.valueOf(data.consumeLong());
              certificateUtilsProvider.generateV1SelfSignedCertificate(
                  keyPair, data.consumeRemainingAsString(), serial);
              break;
            case 4:
              certificateUtilsProvider.getCertificatePolicyList(cert);
              break;
            case 5:
              certificateUtilsProvider.getCRLDistributionPoints(cert);
              break;
            case 6:
              certificateUtilsProvider.createServicesTestCertificate(
                  data.consumeRemainingAsString(), new Date(), new Date(), keyPair);
              break;
          }
          break;
        case 2:
          // PemUtilsProvider
          PemUtilsProvider pemUtilsProvider = cryptoProvider.getPemUtils();
          cert =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          keyPair = KeyUtils.generateRsaKeyPair(2048);

          // Random choose method target for PemUtilsProvider
          switch (data.consumeInt(1, 8)) {
            case 1:
              pemUtilsProvider.decodeCertificate(data.consumeRemainingAsString());
              break;
            case 2:
              pemUtilsProvider.decodePublicKey(data.consumeRemainingAsString());
              break;
            case 3:
              pemUtilsProvider.decodePrivateKey(data.consumeRemainingAsString());
              break;
            case 4:
              pemUtilsProvider.encodeKey(keyPair.getPrivate());
              break;
            case 5:
              pemUtilsProvider.encodeCertificate(cert);
              break;
            case 6:
              pemUtilsProvider.pemToDer(data.consumeRemainingAsString());
              break;
            case 7:
              pemUtilsProvider.removeBeginEnd(data.consumeRemainingAsString());
              break;
            case 8:
              String[] certChain = {data.consumeRemainingAsString()};
              pemUtilsProvider.generateThumbprint(certChain, "X.509");
              break;
          }
          break;
        case 3:
          cryptoProvider.createECParams(
              (String) data.pickValue(Collections.list(ECNamedCurveTable.getNames())));
          break;
        case 4:
          UserIdentityExtractorProvider userIdentityExtractorProvider =
              cryptoProvider.getIdentityExtractorProvider();
          X509Certificate[] certList = new X509Certificate[data.consumeInt(1, 10)];
          for (int i = 0; i < certList.length; i++) {
            certList[i] =
                (X509Certificate)
                    cf.generateCertificate(
                        new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          }
          userIdentityExtractorProvider
              .getCertificatePemIdentityExtractor()
              .extractUserIdentity(certList);
          break;
      }
    } catch (GeneralSecurityException
        | IllegalArgumentException
        | PemException
        | IOException
        | ExceptionInInitializerError e) {
      // Known exception
    }
  }
}

