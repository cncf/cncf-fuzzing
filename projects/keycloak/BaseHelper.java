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
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.profile.PropertiesProfileConfigResolver;
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
import org.keycloak.models.sessions.infinispan.AuthenticationSessionAdapter;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.ProviderManager;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserProfileMetadata;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mockito;

/**
 * This is a base helper class that provides base methods for some fuzzing in the keycloak project.
 */
public class BaseHelper {
  public static KeycloakSession createKeycloakSession(final FuzzedDataProvider data) {
    CryptoIntegration.init(BaseFuzzer.class.getClassLoader());

    DefaultKeycloakSessionFactory res =
        new ResteasyKeycloakSessionFactory() {
          @Override
          public void init() {
            Profile.configure(new PropertiesProfileConfigResolver(System.getProperties()));
            super.init();
          }

          @Override
          protected boolean isEnabled(ProviderFactory factory, Scope scope) {
            return data.consumeBoolean();
          }

          @Override
          protected Map<Class<? extends Provider>, Map<String, ProviderFactory>> loadFactories(
              ProviderManager pm) {
            return super.loadFactories(pm);
          }

          @Override
          public String toString() {
            return "DefaultKeycloakSessionFactory";
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
    return new DefaultAuthenticationFlowContext(data);
  }

  public static AuthenticationFlowContext randomizeContext(
      AuthenticationFlowContext context,
      List<ProviderConfigProperty> properties,
      AuthenticationExecutionModel.Requirement[] requirements) {
    if (context instanceof DefaultAuthenticationFlowContext) {
      if (properties != null) {
        ((DefaultAuthenticationFlowContext) context).randomizeConfig(properties);
      }
      if (requirements != null) {
        ((DefaultAuthenticationFlowContext) context).randomizeRequirement(requirements);
      }
      ((DefaultAuthenticationFlowContext) context).randomizeUserModel();
      ((DefaultAuthenticationFlowContext) context).randomizeExecutionModel();
      ((DefaultAuthenticationFlowContext) context).randomizeHttpRequest();
    }

    return context;
  }

  protected static class DefaultAuthenticationFlowContext implements AuthenticationFlowContext {
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
    private FuzzedDataProvider data;

    private DefaultAuthenticationFlowContext() {}

    public DefaultAuthenticationFlowContext(FuzzedDataProvider data) {
      this.data = data;

      session = createKeycloakSession(data);
      realm = createRealmModel(data);
      sessionModel = new AuthenticationSessionAdapter(session, null, null, null);

      this.newEvent();
      options = new ArrayList<>();
      userSession = null;
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
      error = null;
      eventDetails = "";
      userErrorMessage = "";
      accessCode = "";
    }

    // Object randomize methods
    public void randomizeConfig(List<ProviderConfigProperty> properties) {
      this.config = new AuthenticatorConfigModel();
      this.config.setId("ID");
      this.config.setAlias("ALIAS");

      Map<String, String> map = new HashMap<String, String>();
      for (ProviderConfigProperty property : properties) {
        if (property.getType().equals(ProviderConfigProperty.STRING_TYPE)) {
          map.put(property.getName(), data.consumeString(64));
        }
      }

      this.config.setConfig(map);
    }

    public void randomizeRequirement(AuthenticationExecutionModel.Requirement[] requirements) {
      this.requirement = data.pickValue(requirements);
    }

    public void randomizeUserModel() {
      UserRepresentation rep = new UserRepresentation();

      rep.setAttributes(new HashMap<String, List<String>>());
      rep.setUserProfileMetadata(new UserProfileMetadata());

      rep.setId(data.consumeString(32));
      rep.setUsername(data.consumeString(32));
      rep.setFirstName(data.consumeString(32));
      rep.setLastName(data.consumeString(32));
      rep.setEmail(data.consumeString(32));
      rep.setEmailVerified(data.consumeBoolean());
      rep.setSelf(data.consumeString(32));
      rep.setOrigin(data.consumeString(32));
      rep.setCreatedTimestamp(data.consumeLong());
      rep.setEnabled(data.consumeBoolean());
      rep.setTotp(data.consumeBoolean());
      rep.setFederationLink(data.consumeString(32));
      rep.setServiceAccountClientId(data.consumeString(32));
      rep.setNotBefore(data.consumeInt());

      this.user = RepresentationToModel.createUser(session, realm, rep);
    }

    public void randomizeExecutionModel() {
      this.execution = new AuthenticationExecutionModel();

      this.execution.setId(data.consumeString(32));
      this.execution.setAuthenticatorConfig(data.consumeString(32));
      this.execution.setAuthenticator(data.consumeString(32));
      this.execution.setFlowId(data.consumeString(32));
      this.execution.setAuthenticatorFlow(data.consumeBoolean());
      this.execution.setPriority(data.consumeInt());
      this.execution.setParentFlow(data.consumeString(32));
      this.execution.setRequirement(
          data.pickValue(EnumSet.allOf(AuthenticationExecutionModel.Requirement.class)));
    }

    public void randomizeHttpRequest() {
      MultivaluedMap<String, String> valueMap = new MultivaluedHashMap<String, String>();
      valueMap.add(CredentialRepresentation.SECRET, data.consumeString(32));
      valueMap.add(CredentialRepresentation.PASSWORD, data.consumeString(32));
      valueMap.add(CredentialRepresentation.TOTP, data.consumeString(32));
      valueMap.add(CredentialRepresentation.HOTP, data.consumeString(32));
      valueMap.add(CredentialRepresentation.KERBEROS, data.consumeString(32));
      valueMap.add(AuthenticationManager.FORM_USERNAME, data.consumeString(32));

      this.request = Mockito.mock(HttpRequest.class);
      Mockito.doReturn(valueMap).when(this.request).getDecodedFormParameters();
    }

    // End of object randomize methods

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
    public URI getRefreshUrl(boolean authSessionIdParam) {
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
    public AuthenticationExecutionModel.Requirement getCategoryRequirementFromCurrentFlow(
        String authenticatorCategory) {
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
    public void failure(
        AuthenticationFlowError error,
        Response response,
        String eventDetails,
        String userErrorMessage) {
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
