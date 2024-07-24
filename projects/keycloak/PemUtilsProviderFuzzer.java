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
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.keycloak.common.crypto.PemUtilsProvider;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.crypto.def.BCPemUtilsProvider;
import org.keycloak.crypto.elytron.ElytronPEMUtilsProvider;
import org.keycloak.crypto.fips.BCFIPSPemUtilsProvider;

/** This fuzzer targets the methods in different pem utils provider. */
public class PemUtilsProviderFuzzer extends BaseFuzzer {
  private static CertificateFactory cf;

  public static void fuzzerInitialize() throws GeneralSecurityException {
    cf = CertificateFactory.getInstance("X.509");
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      PemUtilsProvider provider = null;

      Integer choice = data.consumeInt(1, 3);
      switch (choice) {
        case 1:
          provider = new BCPemUtilsProvider();
          break;
        case 2:
          provider = new ElytronPEMUtilsProvider();
          break;
        case 3:
          provider = new BCFIPSPemUtilsProvider();
          break;
      }

      // Random choose method target for PemUtilsProvider
      choice = data.consumeInt(1, 8);
      switch (choice) {
        case 1:
          provider.decodeCertificate(data.consumeRemainingAsString());
          break;
        case 2:
          provider.decodePublicKey(data.consumeRemainingAsString());
          break;
        case 3:
          provider.decodePrivateKey(data.consumeRemainingAsString());
          break;
        case 4:
          provider.encodeKey(KeyUtils.generateRsaKeyPair(2048).getPrivate());
          break;
        case 5:
          X509Certificate cert =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          provider.encodeCertificate(cert);
          break;
        case 6:
          provider.pemToDer(data.consumeRemainingAsString());
          break;
        case 7:
          provider.removeBeginEnd(data.consumeRemainingAsString());
          break;
        case 8:
          String[] certChain = {data.consumeRemainingAsString()};
          provider.generateThumbprint(certChain, "X.509");
          break;
      }
    } catch (GeneralSecurityException | RuntimeException e) {
      // Known exception
    }
  }
}
