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
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.mockito.Mockito;

public class AuthenticationManagerFuzzer {
  private static MockObject mockObject;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create mock object
      mockObject = new MockObject();

      // Create and randomize mock fields of mocked object instance
      mockObject.mockInstance();
      mockObject.randomizeMockData(data);

      switch (data.consumeInt(1, 2)) {
        case 1:
          AuthenticationManager.isSessionValid(mockObject.getRealm(), mockObject.getUserSession());
          break;
        case 2:
          AuthenticationManager.authenticateIdentityCookie(mockObject.getSession(), mockObject.getRealm(), data.consumeBoolean());
          break;
      }
    } catch (IllegalArgumentException e) {
      // Known exception
    } finally {
      cleanUpStaticMockObject();
    }
  }

  private static class MockObject {
    private KeycloakSession session;
    private RealmModel realm;
    private UserSessionModel userSession;

    private void mockInstance() {
      mockKeycloakSession();
      mockRealmModel();
      mockUserSessionModel();
    }

    private void randomizeMockData(FuzzedDataProvider data) {
      randomizeKeycloakSession(data);
      randomizeRealmModel(data);
      randomizeUserSessionModel(data);
    }

    private void mockKeycloakSession() {
      // Create and mock KeycloakSession with static data
      session = Mockito.mock(KeycloakSession.class);
    }

    private void mockRealmModel() {
      // Create and mock RealmModel with static data
      realm = Mockito.mock(RealmModel.class);
    }

    private void mockUserSessionModel() {
      // Create and mock UserSessionModel with static data
      userSession = Mockito.mock(UserSessionModel.class);
    }

    private void randomizeKeycloakSession(FuzzedDataProvider data) {
      // Randomize mock fields of KeycloakSession instance
      CookieProvider cookie = Mockito.mock(CookieProvider.class);
      Mockito.doReturn(data.consumeString(1024)).when(cookie).get(Mockito.any(CookieType.class));
      Mockito.doReturn(cookie).when(session).getProvider(CookieProvider.class);

    } 

    private void randomizeRealmModel(FuzzedDataProvider data) {
      // Randomize mock fields of RealmModel instance
      Mockito.when(realm.isOfflineSessionMaxLifespanEnabled()).thenReturn(data.consumeBoolean());
      Mockito.when(realm.getSsoSessionMaxLifespanRememberMe()).thenReturn(data.consumeInt());
      Mockito.when(realm.getOfflineSessionMaxLifespan()).thenReturn(data.consumeInt());
      Mockito.when(realm.getSsoSessionIdleTimeout()).thenReturn(data.consumeInt());
      Mockito.when(realm.getName()).thenReturn(data.consumeString(data.consumeInt(1, 1024)));
      Mockito.when(realm.getNotBefore()).thenReturn(data.consumeInt());
    }

    private void randomizeUserSessionModel(FuzzedDataProvider data) {
      // Randomize mock fields of UserSessionModel instance
      Mockito.when(userSession.isOffline()).thenReturn(data.consumeBoolean());
      Mockito.when(userSession.isRememberMe()).thenReturn(data.consumeBoolean());
      Mockito.when(userSession.getStarted()).thenReturn(data.consumeInt());
      Mockito.when(userSession.getLastSessionRefresh()).thenReturn(data.consumeInt());
    }

    public KeycloakSession getSession() {
      return this.session;
    }

    public RealmModel getRealm() {
      return this.realm;
    }

    public UserSessionModel getUserSession() {
      return this.userSession;
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

