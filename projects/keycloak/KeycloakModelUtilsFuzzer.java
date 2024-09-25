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
import java.util.Collections;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;

/** This fuzzer targets the static methods in the KeycloakModelUtils class. */
public class KeycloakModelUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      KeycloakSession session = BaseHelper.createKeycloakSession(data);

      switch (data.consumeInt(1, 20)) {
        case 1:
          KeycloakModelUtils.getPemFromKey(
              KeycloakModelUtils.getPublicKey(data.consumeRemainingAsString()));
        case 2:
          KeycloakModelUtils.getPemFromCertificate(
              KeycloakModelUtils.getCertificate(data.consumeRemainingAsString()));
        case 3:
          KeycloakModelUtils.getPemFromKey(
              KeycloakModelUtils.getPrivateKey(data.consumeRemainingAsString()));
        case 4:
          KeycloakModelUtils.getPemFromKey(
              KeycloakModelUtils.getSecretKey(data.consumeRemainingAsString()));
        case 5:
          KeycloakModelUtils.generateKeyPairCertificate(data.consumeRemainingAsString());
        case 6:
          KeycloakModelUtils.generateSecret(
              KeycloakModelUtils.createManagementClient(
                  BaseHelper.createRealmModel(data), data.consumeRemainingAsString()));
        case 7:
          KeycloakModelUtils.generateSecret(
              KeycloakModelUtils.createPublicClient(
                  BaseHelper.createRealmModel(data), data.consumeRemainingAsString()));
        case 8:
          KeycloakModelUtils.searchFor(
              BaseHelper.createRoleModel(data),
              BaseHelper.createRoleModel(data),
              Collections.emptySet());
        case 9:
          KeycloakModelUtils.findUserByNameOrEmail(
              session, BaseHelper.createRealmModel(data), data.consumeRemainingAsString());
        case 10:
          KeycloakModelUtils.cloneContextRealmClientToSession(session.getContext(), session);
          KeycloakModelUtils.cloneContextRealmClientSessionToSession(session.getContext(), session);
        case 11:
          KeycloakModelUtils.createComponentModel(
              data.consumeString(16),
              data.consumeString(16),
              data.consumeString(16),
              data.consumeString(16));
        case 12:
          KeycloakModelUtils.resolveAttribute(
              BaseHelper.randomizeContext(
                      BaseHelper.createAuthenticationFlowContext(data), null, null)
                  .getUser(),
              data.consumeRemainingAsString(),
              true);
        case 13:
          KeycloakModelUtils.resolveAttribute(
              BaseHelper.randomizeContext(
                      BaseHelper.createAuthenticationFlowContext(data), null, null)
                  .getUser(),
              data.consumeRemainingAsString(),
              false);
        case 14:
          KeycloakModelUtils.splitPath(data.consumeRemainingAsString(), true);
        case 15:
          KeycloakModelUtils.splitPath(data.consumeRemainingAsString(), false);
        case 16:
          KeycloakModelUtils.buildGroupPath(data.consumeBoolean(), data.consumeRemainingAsString());
        case 17:
          KeycloakModelUtils.normalizeGroupPath(data.consumeRemainingAsString());
        case 18:
          KeycloakModelUtils.getRoleFromString(
              BaseHelper.createRealmModel(data), data.consumeRemainingAsString());
        case 19:
          KeycloakModelUtils.parseRole(data.consumeRemainingAsString());
        case 20:
          KeycloakModelUtils.isFlowUsed(
              BaseHelper.createKeycloakSession(data),
              BaseHelper.createRealmModel(data),
              BaseHelper.createAuthenticationFlowContext(data).getTopLevelFlow());
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
