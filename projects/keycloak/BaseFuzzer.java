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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
  This is a base fuzzer class that provides base methods for fuzzing
  the keycloak project.
  */
public abstract class BaseFuzzer {
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

  public static RealmModel createRealmModel(FuzzedDataProvider data) {
    RealmManager manager = new RealmManager(createKeycloakSession(data));
    return manager.createRealm("Realm");
  }

  public static String generateServerConfigurationJson() {
    try {
      Map<String, String> map = new HashMap<String, String>();
      map.put("issuer", "issuer");
      map.put("authorization_endpoint", "authorization_endpoint");
      map.put("token_endpoint", "token_endpoint");
      map.put("introspection_endpoint", "introspection_endpoint");
      map.put("userinfo_endpoint", "userinfo_endpoint");
      map.put("end_session_endpoint", "end_session_endpoint");
      map.put("jwks_uri", "jwks_uri");
      map.put("check_session_iframe", "check_session_iframe");
      map.put("resource_registration_endpoint", "resource_registration_endpoint");
      map.put("permission_endpoint", "permission_endpoint");
      map.put("policy_endpoint", "policy_endpoint");
      map.put("registration_endpoint", "registration_endpoint");
      map.put("request_parameter_supported", "true");
      map.put("request_uri_parameter_supported", "true");

      return new ObjectMapper().writeValueAsString(map);
    } catch (JsonProcessingException e) {
      return "{}";
    }
  }

  public static AuthenticationFlowContext createAuthenticationFlowContext(FuzzedDataProvider data) {
    return new DefaultAuthenticationFlowContext();
  }

  private static class DefaultAuthenticationFlowContext implements AuthenticationFlowContext {
    private UserModel user;
    private List<AuthenticationSelectionOption> options;
    private UserSessionModel userSession;
    private AuthenticationSessionModel sessionModel;
    private String flowPath;
    private LoginFormsProvider form;
    private String baseUri;
    private EventBuilder event;
    private KeycloakSession session;
    private RealmModel realm;
    private AuthenticationExecutionModel execution;
    private AuthenticationFlowModel flow;
    private AuthenticatorConfigModel config;
    private ClientConnection connection;
    private UriInfo uriInfo;
    private HttpRequest request;
    private BruteForceProtector protector;
    private FormMessage errorMessage;
    private FormMessage successMessage;
    private FormMessage infoMessage;
    private AuthenticationExecutionModel.Requirement requirement;
    private FlowStatus status;
    private AuthenticationFlowError error;
    private String eventDetails;
    private String userErrorMessage;
    private String accessCode;

    private DefaultAuthenticationFlowContext() {
    }

    public DefaultAuthenticationFlowContext(FuzzedDataProvider data) {
      session = createKeycloakSession(data);
      realm = createRealmModel(data);
      this.newEvent();
      user = null;
      options = new ArrayList<>();
      userSession = null;
      sessionModel = null;
      flowPath = "";
      form = null;
      baseUri = null;
      execution = null;
      flow = null;
      config = null;
      connection = null;
      uriInfo = null;
      request = null;
      protector = null;
      errorMessage = null;
      successMessage = null;
      infoMessage = null;
      requirement = AuthenticationExecutionModel.Requirement.REQUIRED;
      status = null;
      error =null;
      eventDetails = "";
      userErrorMessage = "";
      accessCode = "";
    }

    @Override
    public UserModel getUser() {
      return this.user;
    }

    @Override
    public void setUser(UserModel user) {
      this.user = user;
    }

    @Override
    public void clearUser() {
      this.setUser(null);
    }

    @Override
    public List<AuthenticationSelectionOption> getAuthenticationSelections() {
      return this.options;
    }

    @Override
    public void setAuthenticationSelections(List<AuthenticationSelectionOption> options) {
      this.options = options;
    }

    @Override
    public void attachUserSession(UserSessionModel userSession) {
      this.userSession = userSession;
    }

    public void setAuthenticationSession(AuthenticationSessionModel sessionModel) {
      this.sessionModel = sessionModel;
    }

    @Override
    public AuthenticationSessionModel getAuthenticationSession() {
      return this.sessionModel;
    }

    public void setFlowPath(String flowPath) {
      this.flowPath = flowPath;
    }

    @Override
    public String getFlowPath() {
      return this.flowPath;
    }

    public void setForm(LoginFormsProvider form) {
      this.form = form;
    }

    @Override
    public LoginFormsProvider form() {
      return this.form;
    }

    public void setBaseUri(String baseUri) {
      this.baseUri = baseUri;
    }

    @Override
    public URI getActionUrl(String code) {
      try {
        return new URI(this.baseUri);
      } catch (URISyntaxException e) {
        return null;
      }
    }

    @Override
    public URI getActionTokenUrl(String tokenString) {
      try {
        return new URI(this.baseUri);
      } catch (URISyntaxException e) {
        return null;
      }
    }

    @Override
    public URI getRefreshExecutionUrl() {
      try {
        return new URI(this.baseUri);
      } catch (URISyntaxException e) {
        return null;
      }
    }

    @Override
    public URI getRefreshUrl(boolean authSessionIdParam){
      try {
        return new URI(this.baseUri);
      } catch (URISyntaxException e) {
        return null;
      }
    }

    @Override
    public void cancelLogin() {
      // Do nothing
    }

    @Override
    public void resetFlow() {
      // Do nothing
    }

    @Override
    public void resetFlow(Runnable afterResetListener) {
      // Do nothing
    }

    @Override
    public void fork() {
      // Do nothing
    }

    @Override
    public void forkWithSuccessMessage(FormMessage message) {
      // Do nothing
    }

    @Override
    public void forkWithErrorMessage(FormMessage message) {
      // Do nothing
    }

    @Override
    public EventBuilder getEvent() {
      return this.event;
    }

    @Override
    public EventBuilder newEvent() {
      this.event = new EventBuilder(this.realm, this.session);
      return this.event;
    }

    public void setExecution(AuthenticationExecutionModel execution) {
      this.execution = execution;
    }

    @Override
    public AuthenticationExecutionModel getExecution() {
      return this.execution;
    }

    public void setTopLevelFlow(AuthenticationFlowModel flow) {
      this.flow = flow;
    }

    @Override
    public AuthenticationFlowModel getTopLevelFlow() {
      return this.flow;
    }

    @Override
    public RealmModel getRealm() {
      return this.realm;
    }

    public void setConnection(ClientConnection connection) {
      this.connection = connection;
    }

    @Override
    public ClientConnection getConnection() {
      return this.connection;
    }

    public void setUriInfo(UriInfo uriInfo) {
      this.uriInfo = uriInfo;
    }

    @Override
    public UriInfo getUriInfo() {
      return this.uriInfo;
    }

    @Override
    public KeycloakSession getSession() {
      return this.session;
    }

    public void setRequest(HttpRequest request) {
      this.request = request;
    }

    @Override
    public HttpRequest getHttpRequest() {
      return this.request;
    }

    public void setProtector(BruteForceProtector protector) {
      this.protector = protector;
    }

    @Override
    public BruteForceProtector getProtector() {
      return this.protector;
    }

    public void setAuthenticatorConfig(AuthenticatorConfigModel config) {
      this.config = config;
    }

    @Override
    public AuthenticatorConfigModel getAuthenticatorConfig() {
      return this.config;
    }

    public void setErrorMessage(FormMessage errorMessage) {
      this.errorMessage = errorMessage;
    }

    @Override
    public FormMessage getForwardedErrorMessage() {
      return this.errorMessage;
    }

    public void setSuccessMessage(FormMessage successMessage) {
      this.successMessage = successMessage;
    }

    @Override
    public FormMessage getForwardedSuccessMessage() {
      return this.successMessage;
    }

    @Override
    public void setForwardedInfoMessage(String message, Object... parameters) {
      this.infoMessage = new FormMessage(message, parameters);
    }

    @Override
    public FormMessage getForwardedInfoMessage() {
      return this.infoMessage;
    }

    public void setAccessCode(String code) {
      this.accessCode = code;
    }

    @Override
    public String generateAccessCode() {
      return this.accessCode;
    }

    @Override
    public AuthenticationExecutionModel.Requirement getCategoryRequirementFromCurrentFlow(String authenticatorCategory) {
      return this.requirement;
    }

    @Override
    public void success() {
      // Do nothing
    }

    @Override
    public void failure(AuthenticationFlowError error) {
      // Do nothing
    }

    @Override
    public void failure(AuthenticationFlowError error, Response response) {
      // Do nothing
    }

    @Override
    public void failure(AuthenticationFlowError error, Response response, String eventDetails, String userErrorMessage) {
      // Do nothing
    }

    @Override
    public void challenge(Response challenge) {
      // Do nothing
    }

    @Override
    public void forceChallenge(Response challenge) {
      // Do nothing
    }

    @Override
    public void failureChallenge(AuthenticationFlowError error, Response challenge) {
      // Do nothing
    }

    @Override
    public void attempted() {
      // Do nothing
    }

    public void setStatus(FlowStatus status) {
      this.status = status;
    }

    @Override
    public FlowStatus getStatus() {
      return this.status;
    }

    public void setError(AuthenticationFlowError error) {
      this.error = error;
    }

    @Override
    public AuthenticationFlowError getError() {
      return this.error;
    }

    public void setEventDetails(String eventDetails) {
      this.eventDetails = eventDetails;
    }

    @Override
    public String getEventDetails() {
      return this.eventDetails;
    }

    public void setUserErrorMessage(String errorMessage) {
      this.userErrorMessage = errorMessage;
    }

    @Override
    public String getUserErrorMessage() {
      return this.userErrorMessage;
    }
  }
}

