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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.connections.jpa.JpaConnectionProviderFactory;
import org.keycloak.connections.jpa.DefaultJpaConnectionProviderFactory;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.credential.RecoveryAuthnCodesCredentialProviderFactory;
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.sessions.infinispan.AuthenticationSessionAdapter;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.JpaUserProviderFactory;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.DatastoreProvider;
import org.keycloak.storage.DatastoreProviderFactory;
import org.keycloak.storage.datastore.DefaultDatastoreProviderFactory;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

/**
 * This is a base helper class that provides base methods for some fuzzing in the keycloak project.
 */
public class BaseHelper {
  public static KeycloakSession createKeycloakSession(FuzzedDataProvider data) {
    // Initialise crypto providers
    CryptoIntegration.init(BaseHelper.class.getClassLoader());

    // Initialise a keycloak session object
    MockKeycloakSession session = new MockKeycloakSession();
    session.init(data);

    return session.getSession();
  }

  public static RealmModel createRealmModel(FuzzedDataProvider data) {
    // Initialise KeycloakSession
    KeycloakSession session = createKeycloakSession(data);

    RealmModel realm = Mockito.mock(RealmModel.class);

    return realm;
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

  protected static class MockKeycloakSession {
    private Map<String, Map<String, Object>> providerMap;
    private KeycloakSession session;
    private FuzzedDataProvider data;

    public void init(FuzzedDataProvider data) {
      this.session = Mockito.mock(KeycloakSession.class);

      this.data = data;
      this.providerMap = new HashMap<>();
      this.initCredentialProvider();
      this.initDatastoreProivder();
      this.initUserProvider();
      this.initJpaConnectionProvider();

      Mockito.doAnswer(invocation -> {
        Class clazz = (Class)invocation.getArgument(0);
        return MockKeycloakSession.this.getProvider(clazz);
      }).when(this.session).getProvider(Mockito.any(Class.class));
      Mockito.doAnswer(invocation -> {
          Class clazz = (Class)invocation.getArgument(0);
          String id = (String)invocation.getArgument(1);
          return MockKeycloakSession.this.getProvider(clazz, id);
      }).when(this.session).getProvider(Mockito.any(Class.class), Mockito.any(String.class));
    }

    public KeycloakSession getSession() {
      return this.session;
    }

    private void initCredentialProvider() {
      // Initialise all crendetial provider factories
      List<CredentialProviderFactory> factories = new ArrayList<>();
      factories.add(new OTPCredentialProviderFactory());
      factories.add(new WebAuthnCredentialProviderFactory());
      factories.add(new RecoveryAuthnCodesCredentialProviderFactory());
      factories.add(new WebAuthnPasswordlessCredentialProviderFactory());
      factories.add(new PasswordCredentialProviderFactory());

      // Initialise all credential providers
      Map<String, Object> providers = new HashMap<>();
      for (CredentialProviderFactory factory : factories) {
        providers.put(factory.getId(), factory.create(this.getSession()));
      }

      this.providerMap.put(CredentialProvider.class.getName(), providers);
    }

    private void initDatastoreProivder() {
      // Initialise datastore provider factory
      DatastoreProviderFactory factory = new DefaultDatastoreProviderFactory();

      // Initialise datastore provider
      Map<String, Object> providers = new HashMap<>();
      providers.put(factory.getId(), factory.create(this.getSession()));

      this.providerMap.put(DatastoreProvider.class.getName(), providers);
    }

    private void initUserProvider() {
      // Initialise User provider factory
      JpaUserProviderFactory factory = new JpaUserProviderFactory();

      // Initialise user provider
      Map<String, Object> providers = new HashMap<>();
      providers.put(factory.getId(), factory.create(this.getSession()));

      this.providerMap.put(UserProvider.class.getName(), providers);
    }

    private void initJpaConnectionProvider() {
      // Initialise Jpa connection provider factory
      JpaConnectionProviderFactory factory = new DefaultJpaConnectionProviderFactory();

      // Initialise jpa connection provider
      Map<String, Object> providers = new HashMap<>();
      providers.put(factory.getId(), factory.create(this.getSession()));

      this.providerMap.put(JpaConnectionProvider.class.getName(), providers);
    }

    public Provider getProvider(Class<? extends Provider> clazz) {
      String className = clazz.getName();
      if (providerMap.containsKey(className)) {
        Object[] providers = providerMap.get(className).values().toArray();
        try {
          return clazz.cast(providers[data.consumeInt(0, providers.length - 1)]);
        } catch (ClassCastException e) {
          // Known exception
        }
      }
      return null;
    }

    public Provider getProvider(Class<? extends Provider> clazz, String id) {
      String className = clazz.getName();
      if (providerMap.containsKey(className)) {
        Map<String, Object> providerIdMap = providerMap.get(className);
        try {
          Object provider = providerIdMap.get(id);
          if (provider != null) {
            return clazz.cast(provider);
          }
        } catch (ClassCastException e) {
          // Known exception
        }
      }
      return null;
    }
  }

  protected static class DefaultUserModel extends AbstractUserAdapter.Streams {
    private String username;

    public DefaultUserModel(KeycloakSession session, RealmModel realm, ComponentModel component) {
      super(session, realm, component);
    }

    public void setUsername(String username) {
      this.username = username;
    }

    @Override
    public String getUsername() {
      return this.username;
    }

    @Override
    public SubjectCredentialManager credentialManager() {
      return new UserCredentialManager(session, realm, this);
    }
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
      this.user = new DefaultUserModel(session, realm, new ComponentModel());
      ((DefaultUserModel) this.user).setUsername(data.consumeString(32));
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
