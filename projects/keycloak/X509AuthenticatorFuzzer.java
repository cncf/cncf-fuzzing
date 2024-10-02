// Copyright 2024 the cncf-fuzzing authors
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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsernameFactory;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;

/** This fuzzer targets authenticate methods of different Authenticator implementations. */
public class X509AuthenticatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      AuthenticatorFactory factory = null;
      if (data.consumeBoolean()) {
        factory = new ValidateX509CertificateUsernameFactory();
      } else {
        factory = new X509ClientCertificateAuthenticatorFactory();
      }

      // Fuzz the authenticate method
      Authenticator authenticator = factory.create(null);
      AuthenticationFlowContext context = BaseHelper.createAuthenticationFlowContext(data);
      BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
      authenticator.authenticate(context);
    } catch (RuntimeException e) {
      // Known exception
    } finally {
      BaseHelper.cleanMockObject();
    }
  }
}
