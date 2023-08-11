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
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.ClientModel;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.validation.ClientValidationContext;
import org.keycloak.validation.ClientValidationProvider;
import org.keycloak.validation.DefaultClientValidationProviderFactory;
import org.keycloak.validation.ValidationContext;
import org.mockito.Mockito;

/**
 * This fuzzer targets the validate method in ValidationProvider
 * class in the services validation package.
 */
public class ServicesValidationFuzzer {
  private static ClientValidationProvider validationProvider;
  private static DefaultKeycloakSession session;
  private static ClientModel model;

  public static void fuzzerInitialize() {
    // Initialize KeycloakSession
    DefaultKeycloakSessionFactory dksf = new DefaultKeycloakSessionFactory();
    session = new DefaultKeycloakSession(dksf);

    // Initialize the main validation provider instance
    validationProvider = new DefaultClientValidationProviderFactory().create(session);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create and mock a random client model for validation
      model = Mockito.mock(ClientModel.class);
      randomizeClientModel(data);

      // Create a client validation context object from the random client model
      ClientValidationContext context = new ClientValidationContext(
          data.pickValue(EnumSet.allOf(ValidationContext.Event.class)), session, model);

      // Validate the random client model
      validationProvider.validate(context);
    } catch (NullPointerException e) {
      // Handle the case when the execution environment don't have any profile instance
      if (!e.toString().contains(
              "the return value of \"org.keycloak.common.Profile.getInstance()\" is null")) {
        throw e;
      }
    } catch (RuntimeException e) {
      // Handle the case when the URI builder throws RESTEASY type error from malformed URI
      if (!e.toString().contains("RESTEASY")) {
        throw e;
      }
    } finally {
      cleanUpStaticMockObject();
    }
  }

  private static void randomizeClientModel(FuzzedDataProvider data) {
    Mockito.when(model.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getClientId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getName()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getDescription()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.isEnabled()).thenReturn(data.consumeBoolean());
    Mockito.when(model.isAlwaysDisplayInConsole()).thenReturn(data.consumeBoolean());
    Mockito.when(model.getWebOrigins())
        .thenReturn(Set.of(data.consumeString(data.remainingBytes() / 2)));
    Mockito.when(model.getRedirectUris())
        .thenReturn(Set.of(data.consumeString(data.remainingBytes() / 2)));
    Mockito.when(model.getManagementUrl())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getRootUrl()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getBaseUrl()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getNodeReRegistrationTimeout()).thenReturn(data.consumeInt());
    Mockito.when(model.getClientAuthenticatorType())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.validateSecret(Mockito.any(String.class))).thenReturn(data.consumeBoolean());
    Mockito.when(model.getSecret()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getRegistrationToken())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getProtocol()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getAttribute(Mockito.any(String.class)))
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getAuthenticationFlowBindingOverride(Mockito.any(String.class)))
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.isFrontchannelLogout()).thenReturn(data.consumeBoolean());
    Mockito.when(model.isFullScopeAllowed()).thenReturn(data.consumeBoolean());

    Map<String, String> map = new HashMap<String, String>();
    map.put(data.consumeString(data.remainingBytes() / 2),
        data.consumeString(data.remainingBytes() / 2));

    Mockito.when(model.getAttributes()).thenReturn(map);
    Mockito.when(model.getAuthenticationFlowBindingOverrides()).thenReturn(map);
  }

  private static void cleanUpStaticMockObject() {
    // Deference the static object instance
    model = null;

    // Clean up inline mocks of the mock objects
    Mockito.framework().clearInlineMocks();

    // Suggest the java garbage collector to clean up unused memory
    System.gc();
  }
}
