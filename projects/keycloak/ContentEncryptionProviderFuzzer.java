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
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.EnumSet;
import org.keycloak.common.ClientConnection;
import org.keycloak.crypto.Aes128CbcHmacSha256ContentEncryptionProviderFactory;
import org.keycloak.crypto.Aes128GcmContentEncryptionProviderFactory;
import org.keycloak.crypto.Aes192CbcHmacSha384ContentEncryptionProviderFactory;
import org.keycloak.crypto.Aes192GcmContentEncryptionProviderFactory;
import org.keycloak.crypto.Aes256CbcHmacSha512ContentEncryptionProviderFactory;
import org.keycloak.crypto.Aes256GcmContentEncryptionProviderFactory;
import org.keycloak.crypto.ContentEncryptionProviderFactory;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
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

/** This fuzzer targets the methods in different ocsp provider. */
public class ContentEncryptionProviderFuzzer {
  private static MockObject mockObject;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      ContentEncryptionProviderFactory factory = null;

      // Create and randomize mock fields of mocked object instance
      mockObject = new MockObject();
      mockObject.mockInstance();
      mockObject.randomizeMockData(data);

      Integer choice = data.consumeInt(1, 6);
      switch (choice) {
        case 1:
          factory = new Aes128CbcHmacSha256ContentEncryptionProviderFactory();
          break;
        case 2:
          factory = new Aes128GcmContentEncryptionProviderFactory();
          break;
        case 3:
          factory = new Aes192CbcHmacSha384ContentEncryptionProviderFactory();
          break;
        case 4:
          factory = new Aes192GcmContentEncryptionProviderFactory();
          break;
        case 5:
          factory = new Aes256CbcHmacSha512ContentEncryptionProviderFactory();
          break;
        case 6:
          factory = new Aes256GcmContentEncryptionProviderFactory();
          break;
      }

      JWEEncryptionProvider provider =
          factory.create(mockObject.getSession()).jweEncryptionProvider();

      if (data.consumeBoolean()) {
        provider.encodeJwe(new JWE(data.consumeRemainingAsString()));
      } else {
        provider.verifyAndDecodeJwe(new JWE(data.consumeRemainingAsString()));
      }
    } catch (GeneralSecurityException | JWEException | RuntimeException e) {
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
