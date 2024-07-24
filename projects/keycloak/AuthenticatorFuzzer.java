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
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.AttemptedAuthenticator;
import org.keycloak.authentication.authenticators.access.AllowAccessAuthenticatorFactory;
import org.keycloak.authentication.authenticators.access.DenyAccessAuthenticatorFactory;

/**
  This fuzzer targets authenticate methods of different Authenticator
  implementations.
  */
public class AuthenticatorFuzzer extends BaseFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Authenticator authenticator = null;
      AuthenticationFlowContext context = createAuthenticationFlowContext(data);

      switch(data.consumeInt(1, 3)) {
        case 1:
          authenticator = AttemptedAuthenticator.SINGLETON;
          break;
        case 2:
          authenticator = new AllowAccessAuthenticatorFactory().create(context.getSession());
          break;
        case 3:
          authenticator = new DenyAccessAuthenticatorFactory().create(context.getSession());
          break;
      }

      // Fuzz the authenticate method
      if (authenticator != null) {
        authenticator.authenticate(context);
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}

