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
import jakarta.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.keycloak.authorization.policy.evaluation.DefaultPolicyEvaluator;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.resources.admin.permissions.GroupPermissionEvaluator;
import org.keycloak.utils.CRLUtils;
import org.keycloak.utils.GroupUtils;
import org.keycloak.utils.RegexUtils;
import org.keycloak.utils.SearchQueryUtils;
import org.keycloak.utils.TotpUtils;
import org.mockito.Mockito;

/**
 * This fuzzer targets the methods in different util
 * classes in the services utils package.
 */
public class ServicesUtilsFuzzer {
  private static CertificateFactory cf;
  private static DefaultKeycloakSession session;
  private static EntityManager entityManager;
  private static RealmAdapter realmModel;

  public static void fuzzerInitialize() {
    try {
      // Initialize certificate factory
      cf = CertificateFactory.getInstance("X.509");

      // Initialize KeycloakSession
      DefaultKeycloakSessionFactory dksf = new DefaultKeycloakSessionFactory();
      session = new DefaultKeycloakSession(dksf);

      // Initialize EntityManager
      entityManager = Mockito.mock(EntityManager.class);

      // Initialize RealmAdapter
      realmModel = new RealmAdapter(session, entityManager, new RealmEntity());
    } catch (CertificateException e) {
      // Directly exit if initialisation fails
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomly choose which utils method to invoke
      Integer choice = data.consumeInt(1, 21);
      switch (choice) {
        case 1:
          X509Certificate[] certs = new X509Certificate[3];
          for (int i=0; i<3; i++) {
            certs[i] = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2)));
          }
          X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          CRLUtils.check(certs, crl, session);
          break;
        case 2:
          GroupAdapter group = new GroupAdapter(realmModel, entityManager, new GroupEntity());

          GroupPermissionEvaluator groupPermissions = Mockito.mock(GroupPermissionEvaluator.class);
          Mockito.when(groupPermissions.canList()).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canManage(group)).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canView(group)).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canManage()).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canView()).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.getGroupsWithViewPermission(group)).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canManageMembership(group)).thenReturn(data.consumeBoolean());
          Mockito.when(groupPermissions.canViewMembers(group)).thenReturn(data.consumeBoolean());

          Map<String, Boolean> map = new HashMap<String, Boolean>();
          map.put(data.consumeString(data.remainingBytes() / 2), data.consumeBoolean());
          Mockito.when(groupPermissions.getAccess(group)).thenReturn(map);

          Set<String> set = new HashSet<String>();
          set.add(data.consumeString(data.remainingBytes() / 2));
          Mockito.when(groupPermissions.getGroupsWithViewPermission()).thenReturn(set);

          Boolean exact = data.consumeBoolean();
          Boolean full = data.consumeBoolean();
          GroupUtils.toGroupHierarchy(groupPermissions, group, data.consumeRemainingAsString(), exact, full);
          break;
        case 3:
          RegexUtils.valueMatchesRegex(data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
          break;
        case 4:
          SearchQueryUtils.getFields(data.consumeRemainingAsString());
          break;
        case 5:
          SearchQueryUtils.unescape(data.consumeRemainingAsString());
          break;
        case 6:
          TotpUtils.encode(data.consumeRemainingAsString());
          break;
        case 7:
          UserAdapter userModel = new UserAdapter(session, realmModel, entityManager, new UserEntity());

          TotpUtils.qrCode(data.consumeRemainingAsString(), realmModel, userModel);
          break;
      }
    } catch (GeneralSecurityException e) {
      // Known exception
    }
  }
}
