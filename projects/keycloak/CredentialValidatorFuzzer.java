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
import com.webauthn4j.converter.util.ObjectConverter;
import java.util.List;
import java.util.stream.Stream;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.RecoveryAuthnCodesCredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.RecoveryAuthnCodesCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.mockito.Mockito;

public class CredentialValidatorFuzzer {
  private static CredentialInputValidator validator;
  private static MockObject mockObject;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create and randomize mock fields of mocked object instance
      mockObject = new MockObject();
      mockObject.mockInstance();
      mockObject.randomizeMockData(data);

      switch (data.consumeInt(1, 4)) {
        case 1:
          validator = new OTPCredentialProvider(mockObject.getSession());
          break;
        case 2:
          validator = new PasswordCredentialProvider(mockObject.getSession());
          break;
        case 3:
          validator = new RecoveryAuthnCodesCredentialProvider(mockObject.getSession());
          break;
        case 4:
          validator =
              new WebAuthnCredentialProvider(mockObject.getSession(), new ObjectConverter());
          break;
      }

      // Call to validate credential
      validator.isValid(
          mockObject.getRealmModel(), mockObject.getUserModel(), mockObject.getCredentialInput());
    } catch (IllegalArgumentException e) {
      // Known exception
    } finally {
      cleanUpStaticMockObject();
    }
  }

  private static class MockObject {
    private KeycloakSession session;
    private PasswordHashProvider passwordHashProvider;
    private RealmModel realmModel;
    private UserModel userModel;
    private CredentialInput input;

    private void mockInstance() {
      mockPasswordHashProvider();
      mockUserModel();
      mockRealmModel();
      mockCredentialInput();
      mockKeycloakSession();
    }

    private void randomizeMockData(FuzzedDataProvider data) {
      randomizePasswordHashProvider(data);
      randomizeUserModel(data);
      randomizeCredentialInput(data);
    }

    private void mockPasswordHashProvider() {
      // Create and mock PasswordHashProvider with static data
      passwordHashProvider = Mockito.mock(PasswordHashProvider.class);
    }

    private void mockRealmModel() {
      // Create and mock RealmModel with static data
      realmModel = Mockito.mock(RealmModel.class);
      Mockito.doReturn(PasswordPolicy.empty()).when(realmModel).getPasswordPolicy();
      Mockito.doReturn(OTPPolicy.DEFAULT_POLICY).when(realmModel).getOTPPolicy();
    }

    private void mockUserModel() {
      // Create and mock UsermModel with static data
      userModel = Mockito.mock(UserModel.class);
      Mockito.when(userModel.getUsername()).thenReturn("user");
    }

    private void mockCredentialInput() {
      // Create and mock CredentialInput with static data
      input = Mockito.mock(CredentialInput.class);
    }

    private void mockKeycloakSession() {
      // Create and mock KeycloakSession with static data
      session = Mockito.mock(KeycloakSession.class);

      // Mock SingleUseObjectProvider
      SingleUseObjectProvider singleUseObjectProvider = Mockito.mock(SingleUseObjectProvider.class);
      Mockito.doReturn(true)
          .when(singleUseObjectProvider)
          .putIfAbsent(Mockito.any(String.class), Mockito.any(Long.class));

      Mockito.doReturn(passwordHashProvider)
          .when(session)
          .getProvider(Mockito.any(), Mockito.any(String.class));
      Mockito.doReturn(singleUseObjectProvider).when(session).singleUseObjects();
    }

    private void randomizePasswordHashProvider(FuzzedDataProvider data) {
      // Randomize mock fields of PasswordHashProvider instance
      Mockito.doReturn(data.consumeBoolean())
          .when(passwordHashProvider)
          .verify(Mockito.any(), Mockito.any());
      Mockito.doReturn(data.consumeBoolean())
          .when(passwordHashProvider)
          .policyCheck(Mockito.any(), Mockito.any());
    }

    private void randomizeUserModel(FuzzedDataProvider data) {
      // Randomize mock fields of UserModel instance

      // Create random CredentialModel instance
      CredentialModel model = null;

      switch (data.consumeInt(1, 4)) {
        case 1:
          model =
              OTPCredentialModel.createTOTP(
                  data.consumeString(1024),
                  data.consumeInt(),
                  data.consumeInt(),
                  data.consumeString(1024));
          break;
        case 2:
          model =
              PasswordCredentialModel.createFromValues(
                  data.consumeString(1024),
                  data.consumeBytes(1024),
                  data.consumeInt(),
                  data.consumeString(1024));
          break;
        case 3:
          model =
              RecoveryAuthnCodesCredentialModel.createFromValues(
                  List.of(data.consumeString(1024)), data.consumeLong(), data.consumeString(1024));
          break;
        case 4:
          model =
              WebAuthnCredentialModel.create(
                  data.consumeString(1024),
                  data.consumeString(1024),
                  data.consumeString(1024),
                  data.consumeString(1024),
                  data.consumeString(1024),
                  data.consumeString(1024),
                  data.consumeLong(),
                  data.consumeString(1024));
          break;
      }

      // Mock SubjectCredentialManager instance
      SubjectCredentialManager manager = Mockito.mock(SubjectCredentialManager.class);
      Mockito.doReturn(model).when(manager).getStoredCredentialById(Mockito.any(String.class));
      Stream.Builder<CredentialModel> builder = Stream.builder();
      Mockito.doReturn(builder.add(model).build())
          .when(manager)
          .getStoredCredentialsByTypeStream(Mockito.any(String.class));

      Mockito.doReturn(manager).when(userModel).credentialManager();
    }

    private void randomizeCredentialInput(FuzzedDataProvider data) {
      // Randomize mock fields of CredentialInput instance
      Mockito.doReturn(data.consumeString(1024)).when(input).getCredentialId();
      Mockito.doReturn(data.consumeString(1024)).when(input).getType();
      Mockito.doReturn(data.consumeString(1024)).when(input).getChallengeResponse();
    }

    private KeycloakSession getSession() {
      return session;
    }

    private UserModel getUserModel() {
      return userModel;
    }

    private RealmModel getRealmModel() {
      return realmModel;
    }

    private CredentialInput getCredentialInput() {
      return input;
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
