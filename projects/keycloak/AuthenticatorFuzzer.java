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
import org.keycloak.authentication.authenticators.sessionlimits.UserSessionLimitsAuthenticatorFactory;

/** This fuzzer targets authenticate methods of different Authenticator implementations. */
public class AuthenticatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Authenticator authenticator = null;
      AuthenticationFlowContext context = BaseHelper.createAuthenticationFlowContext(data);

      switch (data.consumeInt(1, 4)) {
        case 1:
          authenticator = AttemptedAuthenticator.SINGLETON;
        case 2:
          authenticator = new AllowAccessAuthenticatorFactory().create(context.getSession());
        case 3:
          authenticator = new DenyAccessAuthenticatorFactory().create(context.getSession());
        case 4:
          AuthenticatorFactory factory = new UserSessionLimitsAuthenticatorFactory();
          context =
              BaseHelper.randomizeContext(
                  context, factory.getConfigProperties(), factory.getRequirementChoices());
          authenticator = factory.create(context.getSession());
      }

      // Fuzz the authenticate method
      authenticator.authenticate(context);  
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
