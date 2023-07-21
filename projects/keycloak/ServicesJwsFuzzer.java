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
import org.keycloak.jose.jws.crypto.HMACProvider;
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
 * This fuzzer targets the methods in DefaultTokenManager
 * class in the services jose jwe package.
 */
public class ServicesJwsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Retrieve mock client model instance
      ClientModel model = mockClientModel(data);

      // Retrieve mock keycloak session instance
      KeycloakSession session = mockKeycloakSession(data, model);

      // Initialize DefaultTokenManager instance
      DefaultTokenManager manager = new DefaultTokenManager(session);

      // Create and mock a token with random TokenCategory
      Token token = Mockito.mock(Token.class);
      Mockito.when(token.getCategory())
          .thenReturn(data.pickValue(EnumSet.allOf(TokenCategory.class)));

      // Randomly execute one of the method in DefaultTokenManager
      switch (data.consumeInt(1, 8)) {
        case 1:
          // Execute the target method
          manager.encode(token);
          break;
        case 2:
          // Execute the target method
          manager.decode(data.consumeRemainingAsString(), Token.class);
          break;
        case 3:
          // Execute the target method
          manager.decodeClientJWT(
              data.consumeRemainingAsString(), model, (joseToken, client) -> {}, Token.class);
          break;
        case 4:
          // Execute the target method
          manager.signatureAlgorithm(data.pickValue(EnumSet.allOf(TokenCategory.class)));
          break;
        case 5:
          // Execute the target method
          manager.encodeAndEncrypt(token);
          break;
        case 6:
          // Execute the target method
          manager.cekManagementAlgorithm(data.pickValue(EnumSet.allOf(TokenCategory.class)));
          break;
        case 7:
          // Execute the target method
          manager.encryptAlgorithm(data.pickValue(EnumSet.allOf(TokenCategory.class)));
          break;
        case 8:
          // Create and mock UserModel with random data
          UserModel userModel = Mockito.mock(UserModel.class);
          Mockito.when(userModel.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));

          // Create and mock UserSessionModel with random data
          UserSessionModel userSessionModel = Mockito.mock(UserSessionModel.class);
          Mockito.when(userSessionModel.getId())
              .thenReturn(data.consumeString(data.remainingBytes() / 2));

          // Create and mock AuthenticatedClientSessionModel with random data
          AuthenticatedClientSessionModel sessionModel =
              Mockito.mock(AuthenticatedClientSessionModel.class);
          Mockito.when(sessionModel.getNote(Mockito.any(String.class)))
              .thenReturn(data.consumeRemainingAsString());
          Mockito.when(sessionModel.getUserSession()).thenReturn(userSessionModel);

          // Execute the target method
          manager.initLogoutToken(model, userModel, sessionModel);
          break;
      }
    } catch (NullPointerException e) {
      // Handle the case when the execution environment don't have any profile instance
      if (!e.toString().contains(
              "the return value of \"org.keycloak.common.Profile.getInstance()\" is null")) {
        throw e;
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }

  private static ClientModel mockClientModel(FuzzedDataProvider data) {
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

    return model;
  }

  private static KeycloakSession mockKeycloakSession(
      FuzzedDataProvider data, ClientModel clientModel) {
    // Create and mock KeycloakSession
    KeycloakSession session = Mockito.mock(KeycloakSession.class);

    // Randomly choose a SignatureProvider
    SignatureProvider signatureProvider = null;
    if (data.consumeBoolean()) {
      signatureProvider =
          new MacSecretSignatureProvider(session, data.consumeString(data.remainingBytes() / 2));
    } else {
      signatureProvider =
          new ECDSASignatureProvider(session, data.consumeString(data.remainingBytes() / 2));
    }

    // Randomly choose a ClientSignatureVerifierProvider
    ClientSignatureVerifierProvider clientSignatureVerifierProvider = null;
    if (data.consumeBoolean()) {
      clientSignatureVerifierProvider = new MacSecretClientSignatureVerifierProvider(
          session, data.consumeString(data.remainingBytes() / 2));
    } else {
      clientSignatureVerifierProvider = new ECDSAClientSignatureVerifierProvider(
          session, data.consumeString(data.remainingBytes() / 2));
    }

    // Create RsaCekManagementProvider instance
    CekManagementProvider cekManagementProvider =
        new RsaCekManagementProvider(session, data.consumeString(data.remainingBytes() / 2));

    // Randomly choose a ContentEncryptionProvider
    ContentEncryptionProvider contentEncryptionProvider = null;
    if (data.consumeBoolean()) {
      contentEncryptionProvider = new AesGcmContentEncryptionProvider(
          session, data.consumeString(data.remainingBytes() / 2));
    } else {
      contentEncryptionProvider = new AesCbcHmacShaContentEncryptionProvider(
          session, data.consumeString(data.remainingBytes() / 2));
    }

    // Create and mock KeyManager
    KeyManager keyManager = Mockito.mock(KeyManager.class);
    Stream.Builder<KeyWrapper> builder = Stream.builder();
    Mockito.when(keyManager.getKeysStream(Mockito.any(RealmModel.class)))
        .thenReturn(builder.add(new KeyWrapper()).build());
    Mockito
        .when(keyManager.getActiveKey(
            Mockito.any(RealmModel.class), Mockito.any(KeyUse.class), Mockito.any(String.class)))
        .thenReturn(new KeyWrapper());

    // Create and mock RealmModel
    RealmModel realmModel = Mockito.mock(RealmModel.class);
    Mockito.when(realmModel.getDefaultSignatureAlgorithm())
        .thenReturn(data.consumeString(data.remainingBytes() / 2));

    // Create and mock KeycloakContext
    KeycloakContext keycloakContext = Mockito.mock(KeycloakContext.class);
    Mockito.when(keycloakContext.getClient()).thenReturn(clientModel);
    Mockito.when(keycloakContext.getRealm()).thenReturn(realmModel);

    // Create mock return for KeycloakSessionObject
    Mockito
        .when(session.getProvider(Mockito.eq(SignatureProvider.class), Mockito.any(String.class)))
        .thenReturn(signatureProvider);
    Mockito
        .when(session.getProvider(
            Mockito.eq(ClientSignatureVerifierProvider.class), Mockito.any(String.class)))
        .thenReturn(clientSignatureVerifierProvider);
    Mockito
        .when(
            session.getProvider(Mockito.eq(CekManagementProvider.class), Mockito.any(String.class)))
        .thenReturn(cekManagementProvider);
    Mockito
        .when(session.getProvider(
            Mockito.eq(ContentEncryptionProvider.class), Mockito.any(String.class)))
        .thenReturn(contentEncryptionProvider);
    Mockito.when(session.keys()).thenReturn(keyManager);
    Mockito.when(session.getContext()).thenReturn(keycloakContext);

    return session;
  }
}
