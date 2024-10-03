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
import org.keycloak.authentication.authenticators.AttemptedAuthenticator;
import org.keycloak.authentication.authenticators.access.AllowAccessAuthenticatorFactory;
import org.keycloak.authentication.authenticators.access.DenyAccessAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpAutoLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpConfirmLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpConfirmOverrideLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpDetectExistingBrokerUserAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpEmailVerificationAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpReviewProfileAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpUsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalLoaAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserAttributeValueFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticatorFactory;
import org.keycloak.authentication.authenticators.directgrant.ValidateOTP;
import org.keycloak.authentication.authenticators.directgrant.ValidatePassword;
import org.keycloak.authentication.authenticators.directgrant.ValidateUsername;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.keycloak.authentication.authenticators.resetcred.ResetOTP;
import org.keycloak.authentication.authenticators.resetcred.ResetPassword;
import org.keycloak.authentication.authenticators.sessionlimits.UserSessionLimitsAuthenticatorFactory;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsernameFactory;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/** This fuzzer targets authenticate methods of different Authenticator implementations. */
public class AuthenticatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    AuthenticatorFactory factory = null;
    Authenticator authenticator = null;
    KeycloakSession session = null;;
    AuthenticationFlowContext context = null;

    try {
      session = BaseHelper.createKeycloakSession(data);
      context = BaseHelper.createAuthenticationFlowContext(data);

      switch (data.consumeInt(1, 25)) {
        case 1:
          authenticator = AttemptedAuthenticator.SINGLETON;
          break;
        case 2:
          factory = new AllowAccessAuthenticatorFactory();
          authenticator = factory.create(session);
          break;
        case 3:
          factory = new DenyAccessAuthenticatorFactory();
          authenticator = factory.create(session);
          break;
        case 4:
          factory = new IdpAutoLinkAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 5:
          factory = new IdpConfirmLinkAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 6:
          factory = new IdpConfirmOverrideLinkAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 7:
          factory = new IdpCreateUserIfUniqueAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 8:
          factory = new IdpDetectExistingBrokerUserAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 9:
          factory = new IdpEmailVerificationAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 10:
          factory = new IdpReviewProfileAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 11:
          factory = new IdpUsernamePasswordFormFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(null);
          break;
        case 12:
          factory = new ConditionalLoaAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(session);
          break;
        case 13:
          factory = new ConditionalRoleAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(session);
          break;
        case 14:
          factory = new ConditionalUserAttributeValueFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(session);
          break;
        case 15:
          factory = new ConditionalUserConfiguredAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(session);
          break;
        case 16:
          authenticator = new ValidateOTP();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 17:
          authenticator = new ValidatePassword();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 18:
          authenticator = new ValidateUsername();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 19:
          authenticator = new ResetCredentialChooseUser();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 20:
          authenticator = new ResetCredentialEmail();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 21:
          authenticator = new ResetOTP();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 22:
          authenticator = new ResetPassword();
          BaseHelper.randomizeContext(context, null, null);
          break;
        case 23:
          factory = new UserSessionLimitsAuthenticatorFactory();
          BaseHelper.randomizeContext(
              context, factory.getConfigProperties(), factory.getRequirementChoices());
          authenticator = factory.create(context.getSession());
          break;
        case 24:
          factory = new ValidateX509CertificateUsernameFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(session);
          break;
        case 25:
          factory = new X509ClientCertificateAuthenticatorFactory();
          BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
          authenticator = factory.create(session);
          break;
      }

      // Fuzz the authenticate method
      authenticator.authenticate(context);
    } catch (RuntimeException e) {
      // Known exception
    } finally {
      factory = null;
      authenticator = null;
      session = null;
      context = null;
      BaseHelper.cleanMockObject();
    }
  }
}
