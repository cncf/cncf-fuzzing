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
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;

/**
  This is a helper class for creating default KeycloakSession
  Currently used by DefaultAuthenticationFlowFuzzer
  */
public abstract class BaseKeycloakSessionFuzzer {
  public static KeycloakSession createKeycloakSession(FuzzedDataProvider data) {
    DefaultKeycloakSessionFactory res = new ResteasyKeycloakSessionFactory() {
      @Override
      public void init() {
        super.init();
      }
    };

    try {
      res.init();
      res.publish(new PostMigrationEvent(res));
      return res.create();
    } catch (RuntimeException ex) {
      res.close();
      throw ex;
    }
  }
}

