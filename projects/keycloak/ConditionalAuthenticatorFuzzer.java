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
import org.keycloak.authentication.authenticators.conditional.ConditionalLoaAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserAttributeValueFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalUserConfiguredAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/** This fuzzer targets authenticate methods of different Authenticator implementations. */
public class ConditionalAuthenticatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      AuthenticatorFactory factory = null;
      AuthenticationFlowContext context = BaseHelper.createAuthenticationFlowContext(data);

      switch (data.consumeInt(1, 4)) {
        case 1:
          factory = new ConditionalLoaAuthenticatorFactory();
        case 2:
          factory = new ConditionalRoleAuthenticatorFactory();
        case 3:
          factory = new ConditionalUserAttributeValueFactory();
        case 4:
          factory = new ConditionalUserConfiguredAuthenticatorFactory();
      }

      // Fuzz the authenticate method
      KeycloakSession session = BaseHelper.createKeycloakSession(data);
      Authenticator authenticator = factory.create(session);
      BaseHelper.randomizeContext(context, null, factory.getRequirementChoices());
      authenticator.authenticate(context);
    } catch (RuntimeException e) {
      // Known exception
    } finally {
      BaseHelper.cleanMockObject();
    }
  }
}
