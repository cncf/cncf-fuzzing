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
import java.util.ServiceConfigurationError;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;
import org.keycloak.representations.AccessToken;

/**
 * This fuzzer targets the methods in the AdapterUtils
 * classes in the adeptor package.
 */
public class AdapterUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Generate random execution choice
      Integer choice = data.consumeInt(1, 3);

      // Initialise the objects and parameters for calling methods
      // in the AdapterUtils class
      KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(
          new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
      AdapterTokenStore tokenStore =
          new SpringSecurityAdapterTokenStoreFactory().createAdapterTokenStore(
              deployment, null, null);
      String tokenString = data.consumeString(data.remainingBytes() / 2);
      String idTokenString = data.consumeString(data.remainingBytes() / 2);
      String refreshToken = data.consumeRemainingAsString();
      RefreshableKeycloakSecurityContext context =
          new RefreshableKeycloakSecurityContext(deployment, tokenStore, tokenString,
              new AccessToken(), idTokenString, new AccessToken(), refreshToken);

      // Randomly call one of the method in the AdapterUtils class
      switch (choice) {
        case 1:
          AdapterUtils.getRolesFromSecurityContext(context);
          break;
        case 2:
          AdapterUtils.getPrincipalName(deployment, new AccessToken());
          break;
        case 3:
          AdapterUtils.createPrincipal(deployment, context);
          break;
      }
    } catch (ServiceConfigurationError | IllegalStateException e) {
      // Known exception
    }
  }
}
