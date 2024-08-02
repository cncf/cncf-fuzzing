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
import org.keycloak.authentication.authenticators.broker.IdpAutoLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpConfirmLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpConfirmOverrideLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpDetectExistingBrokerUserAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpEmailVerificationAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpReviewProfileAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpUsernamePasswordFormFactory;

/** This fuzzer targets authenticate methods of different Authenticator implementations. */
public class BrokerAuthenticatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      AuthenticatorFactory factory = null;

      switch (data.consumeInt(1, 8)) {
        case 1:
          factory = new IdpAutoLinkAuthenticatorFactory();
          break;
        case 2:
          factory = new IdpConfirmLinkAuthenticatorFactory();
          break;
        case 3:
          factory = new IdpConfirmOverrideLinkAuthenticatorFactory();
          break;
        case 4:
          factory = new IdpCreateUserIfUniqueAuthenticatorFactory();
          break;
        case 5:
          factory = new IdpDetectExistingBrokerUserAuthenticatorFactory();
          break;
        case 6:
          factory = new IdpEmailVerificationAuthenticatorFactory();
          break;
        case 7:
          factory = new IdpReviewProfileAuthenticatorFactory();
          break;
        case 8:
          factory = new IdpUsernamePasswordFormFactory();
          break;
      }

      // Fuzz the authenticate method
      if (factory != null) {
        Authenticator authenticator = factory.create(null);
        AuthenticationFlowContext context = BaseHelper.createAuthenticationFlowContext(data);
        BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
        authenticator.authenticate(context);
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
