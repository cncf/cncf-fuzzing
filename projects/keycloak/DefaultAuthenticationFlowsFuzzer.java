// Copyright 2024 the cncf-fuzzing authors
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
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;

/** This fuzzer targets different methods in DefaultAuthenticationFlows */
public class DefaultAuthenticationFlowsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomise choice
      Integer choice = data.consumeInt(1, 10);

      // Initialise string
      String string = data.consumeString(64);

      // Initialise a random RealmModel
      RealmModel realm = BaseHelper.createRealmModel(data);

      switch (choice) {
        case 1:
          DefaultAuthenticationFlows.addFlows(realm);
        case 2:
          DefaultAuthenticationFlows.migrateFlows(realm);
        case 3:
          DefaultAuthenticationFlows.registrationFlow(realm, true);
        case 4:
          DefaultAuthenticationFlows.browserFlow(realm, true);
        case 5:
          DefaultAuthenticationFlows.directGrantFlow(realm, true);
        case 6:
          DefaultAuthenticationFlows.addIdentityProviderAuthenticator(realm, string);
        case 7:
          DefaultAuthenticationFlows.clientAuthFlow(realm);
        case 8:
          DefaultAuthenticationFlows.firstBrokerLoginFlow(realm, true);
        case 9:
          DefaultAuthenticationFlows.samlEcpProfile(realm);
        case 10:
          DefaultAuthenticationFlows.dockerAuthenticationFlow(realm);
      }
    } catch (RuntimeException e) {
      // Known exception
    } finally {
      BaseHelper.cleanMockObject();
    }
  }
}
