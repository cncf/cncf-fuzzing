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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Stream;
import org.keycloak.models.GroupModel;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.resources.admin.permissions.GroupPermissionEvaluator;
import org.keycloak.utils.CRLUtils;
import org.keycloak.utils.GroupUtils;
import org.keycloak.utils.RegexUtils;
import org.keycloak.utils.SearchQueryUtils;
import org.keycloak.utils.TotpUtils;
import org.mockito.Mockito;

/** This fuzzer targets the methods in different util classes in the services utils package. */
public class ServicesUtilsFuzzer {
  private static CertificateFactory cf;
  private static DefaultKeycloakSession session;

  public static void fuzzerInitialize() {
    try {
      // Initialize certificate factory
      cf = CertificateFactory.getInstance("X.509");

      // Initialize KeycloakSession
      DefaultKeycloakSessionFactory dksf = new DefaultKeycloakSessionFactory();
      session = new DefaultKeycloakSession(dksf);
    } catch (CertificateException e) {
      // Directly exit if initialisation fails
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomly choose which utils method to invoke
      Integer choice = data.consumeInt(1, 7);
      switch (choice) {
        case 1:
          // Create certificate and crl from random data
          X509Certificate[] certs = new X509Certificate[3];
          for (int i = 0; i < 3; i++) {
            certs[i] =
                (X509Certificate)
                    cf.generateCertificate(
                        new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          }
          X509CRL crl =
              (X509CRL) cf.generateCRL(new ByteArrayInputStream(data.consumeRemainingAsBytes()));

          // Call target method
          CRLUtils.check(certs, crl, session);
          break;
        case 2:
          // Create and mock GroupModel instance with random data
          GroupModel group = Mockito.mock(GroupModel.class);
          Mockito.when(group.getId()).thenReturn(data.consumeString(data.remainingBytes() / 2));
          Mockito.when(group.getName()).thenReturn(data.consumeString(data.remainingBytes() / 2));
          Mockito.when(group.getParent()).thenReturn(null);

          Stream.Builder<GroupModel> builder = Stream.builder();
          Mockito.when(group.getSubGroupsStream()).thenReturn(builder.build());

          Map<String, List<String>> attributeMap = new HashMap<String, List<String>>();
          attributeMap.put(
              data.consumeString(data.remainingBytes() / 2),
              List.of(data.consumeString(data.remainingBytes() / 2)));
          Mockito.when(group.getAttributes()).thenReturn(attributeMap);

          // Create and mock GroupPermissionEvaluator instance with random data
          GroupPermissionEvaluator groupPermissions = Mockito.mock(GroupPermissionEvaluator.class);
          Mockito.when(groupPermissions.canList()).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canManage(group)).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canView(group)).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canManage()).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canView()).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.getGroupsWithViewPermission(group))
              .thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canManageMembership(group))
              .thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canViewMembers(group)).thenReturn(data.consumeBoolean());

          Map<String, Boolean> permissionMap = new HashMap<String, Boolean>();
          permissionMap.put(data.consumeString(data.remainingBytes() / 2), data.consumeBoolean());
          Mockito.when(groupPermissions.getAccess(group)).thenReturn(permissionMap);

          Set<String> set = new HashSet<String>();
          set.add(data.consumeString(data.remainingBytes() / 2));
          Mockito.when(groupPermissions.getGroupsWithViewPermission()).thenReturn(set);

          // Create and mock RealmModel instance with default policy and random data
          RealmModel realm = Mockito.mock(RealmModel.class);

          // Retrieve random boolean data
          Boolean full = data.consumeBoolean();

          // Call target method
          try {
            GroupUtils.populateGroupHierarchyFromSubGroups(
                session, realm, Stream.of(group), full, groupPermissions);
          } catch (NullPointerException e) {
            // Handle the case when the execution environment don't have any profile instance
            if (!e.toString()
                .contains(
                    "the return value of \"org.keycloak.common.Profile.getInstance()\" is null")) {
              throw e;
            }
          }
          break;
        case 3:
          // Call target method
          RegexUtils.valueMatchesRegex(
              Pattern.quote(data.consumeString(data.remainingBytes() / 2)),
              data.consumeRemainingAsString());
          break;
        case 4:
          // Call target method
          SearchQueryUtils.getFields(data.consumeRemainingAsString());
          break;
        case 5:
          // Call target method
          SearchQueryUtils.unescape(data.consumeRemainingAsString());
          break;
        case 6:
          // Call target method
          TotpUtils.encode(data.consumeRemainingAsString());
          break;
        case 7:
          // Create and mock UserModel instance with random data
          UserModel userModel = Mockito.mock(UserModel.class);
          Mockito.when(userModel.getUsername())
              .thenReturn(data.consumeString(data.remainingBytes() / 2));

          // Create and mock RealmModel instance with default policy and random data
          RealmModel realmModel = Mockito.mock(RealmModel.class);
          Mockito.when(realmModel.getOTPPolicy()).thenReturn(OTPPolicy.DEFAULT_POLICY);
          Mockito.when(realmModel.getName())
              .thenReturn(data.consumeString(data.remainingBytes() / 2));

          // Call target method
          TotpUtils.qrCode(data.consumeRemainingAsString(), realmModel, userModel);
          break;
      }
    } catch (GeneralSecurityException | PatternSyntaxException e) {
      // Known exception
    } catch (RuntimeException e) {
      if (!e.getMessage().contains("com.google.zxing.WriterException")) {
        // Unknown internal exception
        throw e;
      }
    }
  }
}
