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
import org.keycloak.authentication.authenticators.directgrant.ValidateOTP;
import org.keycloak.authentication.authenticators.directgrant.ValidatePassword;
import org.keycloak.authentication.authenticators.directgrant.ValidateUsername;

/** This fuzzer targets authenticate methods of different Authenticator implementations. */
public class DirectGrantAuthenticatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Authenticator authenticator = null;
      AuthenticatorFactory factory = null;
      AuthenticationFlowContext context = BaseHelper.createAuthenticationFlowContext(data);
      BaseHelper.randomizeContext(context, null, null);

      switch (data.consumeInt(1, 3)) {
        case 1:
          authenticator = new ValidateOTP();
        case 2:
          authenticator = new ValidatePassword();
        case 3:
          authenticator = new ValidateUsername();
      }

      // Fuzz the authenticate method
      authenticator.authenticate(context);
    } catch (RuntimeException e) {
      // Known exception
    } finally {
      BaseHelper.cleanMockObject();
    }
  }
}
