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
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.keycloak.Token;
import org.keycloak.TokenCategory;
import org.keycloak.crypto.AesCbcHmacShaContentEncryptionProvider;
import org.keycloak.crypto.AesGcmContentEncryptionProvider;
import org.keycloak.crypto.CekManagementProvider;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.crypto.ContentEncryptionProvider;
import org.keycloak.crypto.ECDSAClientSignatureVerifierProvider;
import org.keycloak.crypto.ECDSASignatureProvider;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.MacSecretClientSignatureVerifierProvider;
import org.keycloak.crypto.MacSecretSignatureProvider;
import org.keycloak.crypto.RsaCekManagementProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jws.DefaultTokenManager;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.mockito.Mockito;

/**
 * This fuzzer targets the methods in DefaultTokenManager class in the services jose jwe package.
 */
public class ServicesJwsFuzzer {
  private static ClientModel clientModel;
  private static RealmModel realmModel;
  private static KeycloakSession session;
  private static DefaultTokenManager manager;
  private static Token token;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      mockObjectInstance();
      randomizeObjectInstance(data);

      // Randomly execute one of the method in DefaultTokenManager
      switch (data.consumeInt(1, 8)) {
        case 1:
          // Execute the target method
          manager.encode(token);
        case 2:
          // Execute the target method
          manager.decode(data.consumeRemainingAsString(), Token.class);
        case 3:
          // Execute the target method
          manager.decodeClientJWT(
              data.consumeRemainingAsString(), clientModel, (joseToken, client) -> {}, Token.class);
        case 4:
          // Execute the target method
          manager.signatureAlgorithm(data.pickValue(EnumSet.allOf(TokenCategory.class)));
        case 5:
          // Execute the target method
          manager.encodeAndEncrypt(token);
        case 6:
          // Execute the target method
          manager.cekManagementAlgorithm(data.pickValue(EnumSet.allOf(TokenCategory.class)));
        case 7:
          // Execute the target method
          manager.encryptAlgorithm(data.pickValue(EnumSet.allOf(TokenCategory.class)));
        case 8:
          // Create and mock UserModel with random data
          UserModel userModel = Mockito.mock(UserModel.class);
          Mockito.when(userModel.getId()).thenReturn(data.consumeString(data.consumeInt(0, 10000)));

          // Create and mock UserSessionModel with random data
          UserSessionModel userSessionModel = Mockito.mock(UserSessionModel.class);
          Mockito.when(userSessionModel.getId())
              .thenReturn(data.consumeString(data.consumeInt(0, 10000)));

          // Create and mock AuthenticatedClientSessionModel with random data
          AuthenticatedClientSessionModel sessionModel =
              Mockito.mock(AuthenticatedClientSessionModel.class);
          Mockito.when(sessionModel.getNote(Mockito.any(String.class)))
              .thenReturn(data.consumeRemainingAsString());
          Mockito.when(sessionModel.getUserSession()).thenReturn(userSessionModel);

          // Execute the target method
          manager.initLogoutToken(clientModel, userModel, sessionModel);
          break;
      }
    } catch (NullPointerException e) {
      // Handle the case when the execution environment don't have any profile instance
      if (!e.toString()
          .contains("the return value of \"org.keycloak.common.Profile.getInstance()\" is null")) {
        throw e;
      }
    } catch (RuntimeException e) {
      if (!isExpectedException(e)) {
        throw e;
      }
    } finally {
      cleanUpStaticMockObject();
    }
  }

  private static void mockObjectInstance() {
    // Create and mock Client Model instance
    clientModel = Mockito.mock(ClientModel.class);

    // Create and mock Realm Model instance
    realmModel = Mockito.mock(RealmModel.class);

    // Create and mock Key Manager instance
    KeyManager keyManager = Mockito.mock(KeyManager.class);
    Stream.Builder<KeyWrapper> builder = Stream.builder();
    Mockito.when(keyManager.getKeysStream(Mockito.any(RealmModel.class)))
        .thenReturn(builder.add(new KeyWrapper()).build());
    Mockito.when(
            keyManager.getActiveKey(
                Mockito.any(RealmModel.class),
                Mockito.any(KeyUse.class),
                Mockito.any(String.class)))
        .thenReturn(new KeyWrapper());

    // Create and mock KeycloakContext
    KeycloakContext keycloakContext = Mockito.mock(KeycloakContext.class);
    Mockito.when(keycloakContext.getClient()).thenReturn(clientModel);
    Mockito.when(keycloakContext.getRealm()).thenReturn(realmModel);

    // Create and mock Keycloak Session instance
    session = Mockito.mock(KeycloakSession.class);
    Mockito.when(session.keys()).thenReturn(keyManager);
    Mockito.when(session.getContext()).thenReturn(keycloakContext);

    // Initialize DefaultTokenManager instance
    manager = new DefaultTokenManager(session);

    // Create and mock Token instance
    token = Mockito.mock(Token.class);
  }

  private static void randomizeObjectInstance(FuzzedDataProvider data) {
    randomizeClientModel(data);
    randomizeRealmModel(data);
    randomizeKeycloakSession(data);
    randomizeToken(data);
  }

  private static void randomizeClientModel(FuzzedDataProvider data) {
    Mockito.when(clientModel.getId()).thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getClientId())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getName()).thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getDescription())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.isEnabled()).thenReturn(data.consumeBoolean());
    Mockito.when(clientModel.isAlwaysDisplayInConsole()).thenReturn(data.consumeBoolean());
    Mockito.when(clientModel.getWebOrigins())
        .thenReturn(Set.of(data.consumeString(data.consumeInt(0, 10000))));
    Mockito.when(clientModel.getRedirectUris())
        .thenReturn(Set.of(data.consumeString(data.consumeInt(0, 10000))));
    Mockito.when(clientModel.getManagementUrl())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getRootUrl())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getBaseUrl())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getNodeReRegistrationTimeout()).thenReturn(data.consumeInt());
    Mockito.when(clientModel.getClientAuthenticatorType())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.validateSecret(Mockito.any(String.class)))
        .thenReturn(data.consumeBoolean());
    Mockito.when(clientModel.getSecret()).thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getRegistrationToken())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getProtocol())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getAttribute(Mockito.any(String.class)))
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getAuthenticationFlowBindingOverride(Mockito.any(String.class)))
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.isFrontchannelLogout()).thenReturn(data.consumeBoolean());
    Mockito.when(clientModel.isFullScopeAllowed()).thenReturn(data.consumeBoolean());

    Map<String, String> map = new HashMap<String, String>();
    map.put(
        data.consumeString(data.consumeInt(0, 10000)),
        data.consumeString(data.consumeInt(0, 10000)));
    Mockito.when(clientModel.getAttributes()).thenReturn(map);
    Mockito.when(clientModel.getAuthenticationFlowBindingOverrides()).thenReturn(map);
  }

  private static void randomizeRealmModel(FuzzedDataProvider data) {
    Mockito.when(realmModel.getDefaultSignatureAlgorithm())
        .thenReturn(data.consumeString(data.consumeInt(0, 10000)));
  }

  private static void randomizeKeycloakSession(FuzzedDataProvider data) {
    // Randomly choose a SignatureProvider
    Mockito.when(token.getCategory())
        .thenReturn(data.pickValue(EnumSet.allOf(TokenCategory.class)));
    SignatureProvider signatureProvider = null;
    if (data.consumeBoolean()) {
      signatureProvider =
          new MacSecretSignatureProvider(session, data.consumeString(data.consumeInt(0, 10000)));
    } else {
      signatureProvider =
          new ECDSASignatureProvider(session, data.consumeString(data.consumeInt(0, 10000)));
    }

    // Randomly choose a ClientSignatureVerifierProvider
    ClientSignatureVerifierProvider clientSignatureVerifierProvider = null;
    if (data.consumeBoolean()) {
      clientSignatureVerifierProvider =
          new MacSecretClientSignatureVerifierProvider(
              session, data.consumeString(data.consumeInt(0, 10000)));
    } else {
      clientSignatureVerifierProvider =
          new ECDSAClientSignatureVerifierProvider(
              session, data.consumeString(data.consumeInt(0, 10000)));
    }

    // Create RsaCekManagementProvider instance
    CekManagementProvider cekManagementProvider =
        new RsaCekManagementProvider(session, data.consumeString(data.consumeInt(0, 10000)));

    // Randomly choose a ContentEncryptionProvider
    ContentEncryptionProvider contentEncryptionProvider = null;
    if (data.consumeBoolean()) {
      contentEncryptionProvider =
          new AesGcmContentEncryptionProvider(
              session, data.consumeString(data.consumeInt(0, 10000)));
    } else {
      contentEncryptionProvider =
          new AesCbcHmacShaContentEncryptionProvider(
              session, data.consumeString(data.consumeInt(0, 10000)));
    }

    // Create mock return for KeycloakSession Object
    Mockito.when(
            session.getProvider(Mockito.eq(SignatureProvider.class), Mockito.any(String.class)))
        .thenReturn(signatureProvider);
    Mockito.when(
            session.getProvider(
                Mockito.eq(ClientSignatureVerifierProvider.class), Mockito.any(String.class)))
        .thenReturn(clientSignatureVerifierProvider);
    Mockito.when(
            session.getProvider(Mockito.eq(CekManagementProvider.class), Mockito.any(String.class)))
        .thenReturn(cekManagementProvider);
    Mockito.when(
            session.getProvider(
                Mockito.eq(ContentEncryptionProvider.class), Mockito.any(String.class)))
        .thenReturn(contentEncryptionProvider);
  }

  private static void randomizeToken(FuzzedDataProvider data) {
    Mockito.when(token.getCategory())
        .thenReturn(data.pickValue(EnumSet.allOf(TokenCategory.class)));
  }

  private static void cleanUpStaticMockObject() {
    // Deference the static object instance
    clientModel = null;
    realmModel = null;
    session = null;
    manager = null;
    token = null;

    // Clean up inline mocks of the mock objects
    Mockito.framework().clearInlineMocks();

    // Suggest the java garbage collector to clean up unused memory
    System.gc();
  }

  private static Boolean isExpectedException(Throwable exc) {
    Class[] expectedExceptions = {JsonProcessingException.class};

    if (exc.getMessage().contains("Bad Base64 input character")) {
      // Catch expected exceptions
    }

    // Check if the exceptions wrapped are expected exceptions
    Throwable cause = exc.getCause();
    if (cause == null) {
      return false;
    } else {
      for (Class cls:expectedExceptions) {
        if (cls.isInstance(cause)) {
          return true;
        }
      }
      return isExpectedException(cause);
    }
  }
}
