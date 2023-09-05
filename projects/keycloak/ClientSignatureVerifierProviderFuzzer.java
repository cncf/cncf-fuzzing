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
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.ES256ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.ES384ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.ES512ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.HS256ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.HS384ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.HS512ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.PS256ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.PS384ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.PS512ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.RS256ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.RS384ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.RS512ClientSignatureVerifierProviderFactory;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.mockito.Mockito;

/** This fuzzer targets the methods in different client signature verifier provider. */
public class ClientSignatureVerifierProviderFuzzer {
  private static MockObject mockObject;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      ClientSignatureVerifierProviderFactory factory = null;

      // Create and randomize mock fields of mocked object instance
      mockObject = new MockObject();
      mockObject.mockInstance();
      mockObject.randomizeMockData(data);

      Integer choice = data.consumeInt(1, 12);
      switch (choice) {
        case 1:
          factory = new ES256ClientSignatureVerifierProviderFactory();
          break;
        case 2:
          factory = new ES384ClientSignatureVerifierProviderFactory();
          break;
        case 3:
          factory = new ES512ClientSignatureVerifierProviderFactory();
          break;
        case 4:
          factory = new HS256ClientSignatureVerifierProviderFactory();
          break;
        case 5:
          factory = new HS384ClientSignatureVerifierProviderFactory();
          break;
        case 6:
          factory = new HS512ClientSignatureVerifierProviderFactory();
          break;
        case 7:
          factory = new PS256ClientSignatureVerifierProviderFactory();
          break;
        case 8:
          factory = new PS384ClientSignatureVerifierProviderFactory();
          break;
        case 9:
          factory = new PS512ClientSignatureVerifierProviderFactory();
          break;
        case 10:
          factory = new RS256ClientSignatureVerifierProviderFactory();
          break;
        case 11:
          factory = new RS384ClientSignatureVerifierProviderFactory();
          break;
        case 12:
          factory = new RS512ClientSignatureVerifierProviderFactory();
          break;
      }

      SignatureVerifierContext verifier =
          factory
              .create(mockObject.getSession())
              .verifier(
                  mockObject.getClient(),
                  new JWSInput(data.consumeString(data.remainingBytes() / 2)));

      verifier.verify(data.consumeBytes(data.remainingBytes() / 2), data.consumeRemainingAsBytes());
    } catch (VerificationException | JWSInputException e) {
      // Known exception
    } finally {
      cleanUpStaticMockObject();
    }
  }

  private static class MockObject {
    private RealmModel realmModel;
    private ClientModel clientModel;
    private HttpHeaders headers;
    private ClientConnection clientConnection;
    private KeycloakUriInfo uriInfo;
    private KeycloakContext context;
    private KeycloakSession session;

    private void mockInstance() {
      mockRealmModel();
      mockClientModel();
      mockHttpHeaders();
      mockClientConnection();
      mockKeycloakUriInfo();
      mockKeycloakContext();
      mockKeycloakSession();
    }

    private void randomizeMockData(FuzzedDataProvider data) {
      randomizeRealmModel(data);
      randomizeClientModel(data);
      randomizeHttpHeaders(data);
      randomizeClientConnection(data);
      randomizeKeycloakUriInfo(data);
      randomizeKeycloakSession(data);
    }

    private void mockRealmModel() {
      // Create and mock RealmModel with static data
      realmModel = Mockito.mock(RealmModel.class);
      Mockito.when(realmModel.getName()).thenReturn("realm");
    }

    private void mockClientModel() {
      // Create and mock ClientModel with static data
      clientModel = Mockito.mock(ClientModel.class);
      Mockito.when(clientModel.getRealm()).thenReturn(realmModel);
    }

    private void mockHttpHeaders() {
      // Create and mock HttpHeaders with static data
      headers = Mockito.mock(HttpHeaders.class);
    }

    private void mockClientConnection() {
      // Create and mock ClientConnection with static data
      clientConnection = Mockito.mock(ClientConnection.class);
      Mockito.when(clientModel.getAttributes()).thenReturn(Collections.emptyMap());
    }

    private void mockKeycloakUriInfo() {
      uriInfo = Mockito.mock(KeycloakUriInfo.class);
      try {
        Mockito.when(uriInfo.getBaseUri()).thenReturn(new URI("http://localhost"));
      } catch (URISyntaxException e) {
        // Known exception
      }
    }

    private void mockKeycloakContext() {
      // Create and mock KeycloakContext with static data
      context = Mockito.mock(KeycloakContext.class);
      Mockito.when(context.getClient()).thenReturn(clientModel);
      Mockito.when(context.getRealm()).thenReturn(realmModel);
      Mockito.when(context.getRequestHeaders()).thenReturn(headers);
      Mockito.when(context.getConnection()).thenReturn(clientConnection);
      Mockito.when(context.getUri()).thenReturn(uriInfo);
    }

    private void mockKeycloakSession() {
      // Create and mock KeycloakSession with static data
      session = Mockito.mock(KeycloakSession.class);

      // Create and mock KeycloakSessionFactory object
      KeycloakSessionFactory keycloakSessionFactory = Mockito.mock(KeycloakSessionFactory.class);
      Mockito.doReturn(session).when(keycloakSessionFactory).create();

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

      // Create mock return for KeycloakSessionObject
      Mockito.when(session.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);
      Mockito.when(session.getContext()).thenReturn(context);
      Mockito.doReturn(realmProvider).when(session).realms();
      Mockito.doReturn(clientProvider).when(session).clients();
    }

    private void randomizeRealmModel(FuzzedDataProvider data) {
      // Randomize mock fields of Realm Model instance
      Mockito.when(realmModel.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(realmModel.isEventsEnabled()).thenReturn(data.consumeBoolean());
      Mockito.when(realmModel.getDefaultSignatureAlgorithm())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
    }

    private void randomizeClientModel(FuzzedDataProvider data) {
      // Randomize mock fields of Client Model instance
      Mockito.when(clientModel.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(clientModel.getClientId())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(clientModel.getName()).thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(clientModel.validateSecret(Mockito.any(String.class)))
          .thenReturn(data.consumeBoolean());
      Mockito.when(clientModel.getSecret())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
    }

    private void randomizeHttpHeaders(FuzzedDataProvider data) {
      // Randomize mock fields of Http Headers instance
      MultivaluedMap<String, String> map = new MultivaluedHashMap<String, String>();
      map.add("Origin", "Origin" + data.consumeString(data.remainingBytes() / 2));

      Mockito.when(headers.getRequestHeaders()).thenReturn(map);
    }

    private void randomizeClientConnection(FuzzedDataProvider data) {
      // Randomize mock fields of Client Connection instance
      Mockito.when(clientConnection.getRemoteAddr())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(clientConnection.getRemoteHost())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(clientConnection.getLocalAddr())
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(clientConnection.getRemotePort()).thenReturn(data.consumeInt(1, 65536));
      Mockito.when(clientConnection.getLocalPort()).thenReturn(data.consumeInt(1, 65536));
    }

    private void randomizeKeycloakUriInfo(FuzzedDataProvider data) {
      // Randomize mock fields of Keycloak Uri Info instance
      MultivaluedMap<String, String> map = new MultivaluedHashMap<String, String>();
      map.add(
          data.consumeString(data.remainingBytes() / 2),
          data.consumeString(data.remainingBytes() / 2));
      Mockito.when(uriInfo.getQueryParameters()).thenReturn(map);
    }

    private void randomizeKeycloakSession(FuzzedDataProvider data) {
      // Randomize mock fields of Keycloak Session instance

      // Create and mock TransactionManager
      KeycloakTransactionManager transactionManager =
          Mockito.mock(KeycloakTransactionManager.class);
      Mockito.when(transactionManager.getJTAPolicy())
          .thenReturn(data.pickValue(EnumSet.allOf(KeycloakTransactionManager.JTAPolicy.class)));

      // Create mock return for KeycloakSession instance
      Mockito.when(session.getTransactionManager()).thenReturn(transactionManager);
    }

    private KeycloakSession getSession() {
      return session;
    }

    private ClientModel getClient() {
      return clientModel;
    }
  }

  private static void cleanUpStaticMockObject() {
    // Deference static mock object instance
    mockObject = null;

    // Clean up inline mocks of the mock objects
    Mockito.framework().clearInlineMocks();

    // Suggest the java garbage collector to clean up unused memory
    System.gc();
  }
}
