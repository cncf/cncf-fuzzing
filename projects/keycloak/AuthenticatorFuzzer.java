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
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.access.AllowAccessAuthenticatorFactory;
import org.keycloak.authentication.authenticators.access.DenyAccessAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpAutoLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpConfirmLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpDetectExistingBrokerUserAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpEmailVerificationAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpReviewProfileAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpUsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsernameFactory;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mockito;

public class AuthenticatorFuzzer {
  private static MockObject mockObject;
  private static CertificateFactory cf;

  public static void fuzzerInitialize() {
    try {
      // Initialize certificate factory
      cf = CertificateFactory.getInstance("X.509");
    } catch (GeneralSecurityException e) {
      // Directly exit if initialisation fails
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create mock object
      mockObject = new MockObject();

      // Create and randomize mock fields of mocked object instance
      mockObject.mockInstance();
      mockObject.randomizeMockData(data);

      AuthenticatorFactory factory = null;

      switch (data.consumeInt(1, 11)) {
        case 1:
          factory = new AllowAccessAuthenticatorFactory();
          break;
        case 2:
          factory = new DenyAccessAuthenticatorFactory();
          break;
        case 3:
          factory = new IdpAutoLinkAuthenticatorFactory();
          break;
        case 4:
          factory = new IdpConfirmLinkAuthenticatorFactory();
          break;
        case 5:
          factory = new IdpCreateUserIfUniqueAuthenticatorFactory();
          break;
        case 6:
          factory = new IdpDetectExistingBrokerUserAuthenticatorFactory();
          break;
        case 7:
          factory = new IdpEmailVerificationAuthenticatorFactory();
          break;
        case 8:
          factory = new IdpReviewProfileAuthenticatorFactory();
          break;
        case 9:
          factory = new IdpUsernamePasswordFormFactory();
          break;
        case 10:
          factory = new ValidateX509CertificateUsernameFactory();
          break;
        case 11:
          factory = new X509ClientCertificateAuthenticatorFactory();
          break;
      }

      if (factory != null) {
        Authenticator authenticator = factory.create(mockObject.getSession());
        if (authenticator != null) {
          AuthenticationExecutionModel model = generateRandomModel(data);
          List<AuthenticationExecutionModel> executions = generateRandomModels(data);

          AuthenticationProcessor processor = new AuthenticationProcessor();
          processor.setAuthenticationSession(mockObject.getSessionModel());
          processor.setSession(mockObject.getSession());
          processor.setRealm(mockObject.getRealm());
          processor.setConnection(mockObject.getConnection());
          processor.newEvent();

          AuthenticationFlowContext context =
              processor.createAuthenticatorContext(model, authenticator, executions);

          switch (data.consumeInt(1, 4)) {
            case 1:
              authenticator.authenticate(context);
              break;
            case 2:
              authenticator.action(context);
              break;
            case 3:
              authenticator.configuredFor(
                  mockObject.getSession(), mockObject.getRealm(), mockObject.getUser());
              break;
            case 4:
              authenticator.areRequiredActionsEnabled(
                  mockObject.getSession(), mockObject.getRealm());
              break;
          }
        }
      }
    } catch (IllegalArgumentException e) {
      // Known exception
    } finally {
      cleanUpStaticMockObject();
    }
  }

  private static AuthenticationExecutionModel generateRandomModel(FuzzedDataProvider data) {
    AuthenticationExecutionModel model = new AuthenticationExecutionModel();

    model.setId(data.consumeString(1024));
    model.setAuthenticatorConfig(data.consumeString(1024));
    model.setAuthenticator(data.consumeString(1024));
    model.setFlowId(data.consumeString(1024));
    model.setParentFlow(data.consumeString(1024));
    model.setAuthenticatorFlow(data.consumeBoolean());
    model.setPriority(data.consumeInt());
    model.setRequirement(
        data.pickValue(EnumSet.allOf(AuthenticationExecutionModel.Requirement.class)));

    return model;
  }

  private static List<AuthenticationExecutionModel> generateRandomModels(FuzzedDataProvider data) {
    List<AuthenticationExecutionModel> list = new LinkedList<AuthenticationExecutionModel>();

    for (int i = 0; i < data.consumeInt(1, 5); i++) {
      list.add(generateRandomModel(data));
    }

    return list;
  }

  private static class MockObject {
    private KeycloakSession session;
    private AuthenticationSessionModel model;
    private ClientConnection clientConnection;
    private X509ClientCertificateLookup certificateProvider;
    private RealmModel realm;
    private UserModel user;

    private void mockInstance() {
      mockAuthenticationSessionModel();
      mockClientConnection();
      mockRealmModel();
      mockUserModel();
      mockCertificateProvider();
      mockKeycloakSession();
    }

    private void randomizeMockData(FuzzedDataProvider data) {
      randomizeCertificateProvider(data);
      randomizeAuthenticationSessionModel(data);
      randomizeClientConnection(data);
      randomizeRealmModel(data);
      randomizeUserModel(data);
    }

    private void mockAuthenticationSessionModel() {
      // Create and mock AuthenticationSessionModel with static data
      model = Mockito.mock(AuthenticationSessionModel.class);

      Mockito.doReturn(realm).when(model).getRealm();
    }

    private void mockClientConnection() {
      // Create and mock ClientConnection with static data
      clientConnection = Mockito.mock(ClientConnection.class);
    }

    private void mockRealmModel() {
      // Create and mock RealmModel with static data
      realm = Mockito.mock(RealmModel.class);
    }

    private void mockUserModel() {
      // Create and mock UserModel with static data
      user = Mockito.mock(UserModel.class);
    }

    private void mockCertificateProvider() {
      // Create and mock X509ClientCertificateLookup with static data
      certificateProvider = Mockito.mock(X509ClientCertificateLookup.class);
    }

    private void mockKeycloakSession() {
      // Create and mock KeycloakSession with static data
      session = Mockito.mock(DefaultKeycloakSession.class);

      Mockito.doReturn(certificateProvider)
          .when(session)
          .getProvider(X509ClientCertificateLookup.class);
      Mockito.doReturn(new DefaultKeycloakSessionFactory())
          .when(session)
          .getKeycloakSessionFactory();
    }

    private void randomizeAuthenticationSessionModel(FuzzedDataProvider data) {
      // Randomize mock fields of AuthenticationSessionModel instance
      Mockito.doReturn(data.consumeString(1024)).when(model).getAuthNote(Mockito.any(String.class));
    }

    private void randomizeClientConnection(FuzzedDataProvider data) {
      // Randomize mock fields of Client Connection instance
      Mockito.when(clientConnection.getRemoteAddr()).thenReturn(data.consumeString(1024));
      Mockito.when(clientConnection.getRemoteHost()).thenReturn(data.consumeString(1024));
      Mockito.when(clientConnection.getLocalAddr()).thenReturn(data.consumeString(1024));
      Mockito.when(clientConnection.getRemotePort()).thenReturn(data.consumeInt(1, 65536));
      Mockito.when(clientConnection.getLocalPort()).thenReturn(data.consumeInt(1, 65536));
    }

    private void randomizeRealmModel(FuzzedDataProvider data) {
      // Randomize mock fields of RealmModel instance
      Mockito.doReturn(data.consumeBoolean()).when(realm).isRegistrationEmailAsUsername();
      Mockito.when(realm.getId()).thenReturn(data.consumeString(1024));
      Mockito.when(realm.isEventsEnabled()).thenReturn(data.consumeBoolean());
      Mockito.when(realm.getDefaultSignatureAlgorithm()).thenReturn(data.consumeString(1024));
    }

    private void randomizeUserModel(FuzzedDataProvider data) {
      // Randomize mock fields of UserModel instance
      Mockito.when(user.getUsername()).thenReturn(data.consumeString(1024));
    }

    private void randomizeCertificateProvider(FuzzedDataProvider data) {
      // Randomize mock fields of CertificateProvider instance

      // Generate certificate chain
      Integer size = data.consumeInt(1, 5);
      X509Certificate[] certs = new X509Certificate[size];

      try {
        for (Integer i = 0; i < size; i++) {
          certs[i] =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
        }
        Mockito.doReturn(certs).when(certificateProvider).getCertificateChain(Mockito.any());
      } catch (GeneralSecurityException e) {
        // Known exception
      }
    }

    public AuthenticationSessionModel getSessionModel() {
      return model;
    }

    public ClientConnection getConnection() {
      return clientConnection;
    }

    public RealmModel getRealm() {
      return realm;
    }

    public UserModel getUser() {
      return user;
    }

    public KeycloakSession getSession() {
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
