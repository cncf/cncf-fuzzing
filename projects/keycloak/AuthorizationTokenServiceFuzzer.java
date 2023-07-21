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
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.DefaultAuthorizationProviderFactory;
import org.keycloak.authorization.authorization.AuthorizationTokenService;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.resources.Cors;
import org.mockito.Mockito;

/**
 * This fuzzer targets the methods in DefaultTokenManager
 * class in the services jose jwe package.
 */
public class AuthorizationTokenServiceFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create and mock RealmModel
      RealmModel realmModel = Mockito.mock(RealmModel.class);
      Mockito.when(realmModel.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(realmModel.isEventsEnabled()).thenReturn(data.consumeBoolean());
      Mockito.when(realmModel.getName()).thenReturn("realm");
      Mockito.when(realmModel.getDefaultSignatureAlgorithm())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));

      // Retrieve mock client model instance
      ClientModel clientModel = mockClientModel(data, realmModel);

      // Retrieve mock keycloak session instance
      KeycloakSession session = mockKeycloakSession(data, clientModel, realmModel);

      // Retrieve AuthorizationTokenService instance
      AuthorizationTokenService service = AuthorizationTokenService.instance();

      // Retrieve a mocked KeycloakAuthorizationRequest instance
      AuthorizationTokenService.KeycloakAuthorizationRequest request =
          mockKeycloakAuthorizationRequest(data, session, realmModel);

      // Invoke the authorize method
      service.authorize(request);
    } catch (CorsErrorResponseException e) {
      // Known exception
    }
  }

  private static ClientModel mockClientModel(FuzzedDataProvider data, RealmModel realmModel) {
    // Create and mock ClientModel instance with random data
    ClientModel model = Mockito.mock(ClientModel.class);
    Mockito.when(model.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getClientId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getName()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.getDescription()).thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(model.isEnabled()).thenReturn(data.consumeBoolean());
    Mockito.when(model.isAlwaysDisplayInConsole()).thenReturn(data.consumeBoolean());
    Mockito.when(model.isSurrogateAuthRequired()).thenReturn(data.consumeBoolean());
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
    Mockito.when(model.getRealm()).thenReturn(realmModel);

    return model;
  }

  private static KeycloakSession mockKeycloakSession(
      FuzzedDataProvider data, ClientModel clientModel, RealmModel realmModel) {
    // Create and mock KeycloakSession
    KeycloakSession session = Mockito.mock(KeycloakSession.class);

    // Create and mock KeycloakSessionFactory object
    KeycloakSessionFactory keycloakSessionFactory = Mockito.mock(KeycloakSessionFactory.class);
    Mockito.doReturn(session).when(keycloakSessionFactory).create();

    // Retrieve mock HttpHeaders instance
    HttpHeaders headers = mockHttpHeaders(data);

    // Retrieve mock ClientConnection instance
    ClientConnection connection = mockClientConnection(data);

    MultivaluedMap<String, String> map = new MultivaluedHashMap<String, String>();
    map.add(data.consumeString(data.remainingBytes() / 2),
        data.consumeString(data.remainingBytes() / 2));

    // Create and mock UriInfo instance
    KeycloakUriInfo uriInfo = Mockito.mock(KeycloakUriInfo.class);
    try {
      Mockito.when(uriInfo.getBaseUri()).thenReturn(new URI("http://localhost"));
    } catch (URISyntaxException e) {
      // Known exception
    }
    Mockito.when(uriInfo.getQueryParameters()).thenReturn(map);

    // Create and mock KeycloakContext
    KeycloakContext keycloakContext = Mockito.mock(KeycloakContext.class);
    Mockito.when(keycloakContext.getClient()).thenReturn(clientModel);
    Mockito.when(keycloakContext.getRealm()).thenReturn(realmModel);
    Mockito.when(keycloakContext.getRequestHeaders()).thenReturn(headers);
    Mockito.when(keycloakContext.getConnection()).thenReturn(connection);
    Mockito.when(keycloakContext.getUri()).thenReturn(uriInfo);

    // Create and mock RealmProvider
    RealmProvider realmProvider = Mockito.mock(RealmProvider.class);
    Mockito.when(realmProvider.getRealm(Mockito.any())).thenReturn(realmModel);
    Mockito.when(realmProvider.getRealmByName(Mockito.any())).thenReturn(realmModel);

    // Create and mock ClientProvider
    ClientProvider clientProvider = Mockito.mock(ClientProvider.class);
    Mockito.when(clientProvider.getClientById(Mockito.any(), Mockito.any()))
        .thenReturn(clientModel);
    Mockito.when(clientProvider.getClientByClientId(Mockito.any(), Mockito.any()))
        .thenReturn(clientModel);

    // Create and mock TransactionManager
    KeycloakTransactionManager transactionManager = Mockito.mock(KeycloakTransactionManager.class);
    Mockito.when(transactionManager.getJTAPolicy())
        .thenReturn(data.pickValue(EnumSet.allOf(KeycloakTransactionManager.JTAPolicy.class)));

    // Create mock return for KeycloakSessionObject
    Mockito.when(session.getContext()).thenReturn(keycloakContext);
    Mockito.when(session.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);
    Mockito.when(session.getTransactionManager()).thenReturn(transactionManager);
    Mockito.doReturn(realmProvider).when(session).realms();
    Mockito.doReturn(clientProvider).when(session).clients();

    return session;
  }

  private static HttpHeaders mockHttpHeaders(FuzzedDataProvider data) {
    // Create and mock HttpHeaders
    HttpHeaders headers = Mockito.mock(HttpHeaders.class);
    MultivaluedMap<String, String> map = new MultivaluedHashMap<String, String>();
    map.add("Origin", "Origin" + data.consumeString(data.remainingBytes() / 2));
    Mockito.when(headers.getRequestHeaders()).thenReturn(map);

    return headers;
  }

  private static HttpRequest mockHttpRequest(FuzzedDataProvider data) {
    // Prepare HttpRequest instance with the mocked object
    HttpRequest request = Mockito.mock(HttpRequest.class);
    Mockito.doReturn(mockHttpHeaders(data)).when(request).getHttpHeaders();

    return request;
  }

  private static ClientConnection mockClientConnection(FuzzedDataProvider data) {
    // Mock ClientConnection instance
    ClientConnection clientConnection = Mockito.mock(ClientConnection.class);
    Mockito.when(clientConnection.getRemoteAddr())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(clientConnection.getRemoteHost())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(clientConnection.getLocalAddr())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));
    Mockito.when(clientConnection.getRemotePort()).thenReturn(data.consumeInt(1, 65536));
    Mockito.when(clientConnection.getLocalPort()).thenReturn(data.consumeInt(1, 65536));

    return clientConnection;
  }

  private static AuthorizationTokenService.KeycloakAuthorizationRequest
  mockKeycloakAuthorizationRequest(
      FuzzedDataProvider data, KeycloakSession session, RealmModel realmModel) {
    // Create AuthorizationProvider instance
    AuthorizationProvider authorizationProvider =
        new DefaultAuthorizationProviderFactory().create(session);

    // Retrieve mock ClientConnection instance
    ClientConnection clientConnection = mockClientConnection(data);

    // Create EventBuilder instance
    EventBuilder eventBuilder = new EventBuilder(realmModel, session, clientConnection);
    eventBuilder.event(data.pickValue(EnumSet.allOf(EventType.class)));

    // Retrieve mock HttpRequest instance
    HttpRequest httpRequest = mockHttpRequest(data);

    // Create Cors instance
    Cors cors = new Cors(httpRequest);

    // Create TokenManager instance
    TokenManager tokenManager = new TokenManager();

    return new AuthorizationTokenService.KeycloakAuthorizationRequest(
        authorizationProvider, tokenManager, eventBuilder, httpRequest, cors, clientConnection);
  }
}
