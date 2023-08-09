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
import com.code_intelligence.jazzer.api.BugDetectors;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.EnumSet;
import java.util.Map;
import java.util.function.BiPredicate;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.keycloak.adapters.authorization.integration.elytron.ServletHttpRequest;
import org.keycloak.adapters.authorization.integration.elytron.ServletHttpResponse;
import org.keycloak.adapters.authorization.spi.HttpRequest;
import org.keycloak.adapters.authorization.spi.HttpResponse;
import org.keycloak.protocol.oidc.client.authentication.ClientCredentialsProvider;
import org.keycloak.protocol.oidc.client.authentication.ClientCredentialsProviderUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.mockito.Mockito;

/**
 * This fuzzer creates configuration objects and mock
 * HttpRequest and HttpResponse to fuzz the enforce
 * method of the PolicyEnforcer class of the authz package.
 */
public class PolicyEnforcerFuzzer {
  private static HttpServletRequest servletRequest;
  private static HttpServletResponse servletResponse;
  private static HttpRequest request;
  private static HttpResponse response;
  private static MockWebServer server;
  private static MockResponse mockResponse;
  private static PolicyEnforcerConfig enforcerConfig;
  private static ClientCredentialsProvider provider;

  public static void fuzzerInitialize() {
    try {
      // Start the mock web server
      server = new MockWebServer();
      server.start();

      // Retrieve host name, port and url of the mock web server
      String serverHost = server.getHostName();
      Integer serverPort = server.getPort();
      String serverUrl = "http://" + serverHost + ":" + serverPort;

      // Mock HttpServletRequest, HttpServletResponse and TokenPrincipal
      servletRequest = Mockito.mock(HttpServletRequest.class);
      servletResponse = Mockito.mock(HttpServletResponse.class);
      TokenPrincipal principal = Mockito.mock(TokenPrincipal.class);

      // Mock key method of the TokenPrincipal instance
      Mockito.when(principal.getToken()).thenReturn(new AccessToken());

      // Prepare HttpRequest and HttpResponse instance with the mocked object
      request = new ServletHttpRequest(servletRequest, principal);
      response = new ServletHttpResponse(servletResponse);

      // Prepare Mock Response instance
      mockResponse = new MockResponse();
      mockResponse.addHeader("Content-Type", "application/json");

      // Initialize enforcer config instance with random set of request and response data
      enforcerConfig = new PolicyEnforcerConfig();
      // Set the redirect string
      enforcerConfig.setOnDenyRedirectTo(serverUrl);
      // Randomly config the string data for the config
      enforcerConfig.setAuthServerUrl(serverUrl);
      enforcerConfig.setRealm("");
      enforcerConfig.setResource("");

      // Prepare client credentials provider
      provider = ClientCredentialsProviderUtils.bootstrapClientAuthenticator(new AdapterConfig());

      // Enable the fuzzer to connect only to the mock web server, deny any other connections
      BugDetectors.allowNetworkConnections(
          (host, port) -> host.equals(serverHost) && port.equals(serverPort));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    // Shutdown the mock web server
    try {
      if (server != null) {
        server.shutdown();
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create a random mock response for the mock web server
      // Then enqueue to the server to serve possible request
      mockResponse.setBody(data.consumeString(data.remainingBytes() / 2));
      server.enqueue(mockResponse);

      // Randomly choose the enforcement mode
      enforcerConfig.setEnforcementMode(
          data.pickValue(EnumSet.allOf(PolicyEnforcerConfig.EnforcementMode.class)));
      // Randomly turn on and off for using http method as scope
      enforcerConfig.setHttpMethodAsScope(data.consumeBoolean());

      // Prepare credential map with random data
      Map<String, Object> map = enforcerConfig.getCredentials();
      map.put(data.consumeString(data.remainingBytes() / 2),
          data.consumeString(data.remainingBytes() / 2));
      enforcerConfig.setCredentials(map);

      // Build the policy enforcer with random data and the config and provider object initialised
      // above
      PolicyEnforcer enforcer = PolicyEnforcer.builder()
                                    .clientId(data.consumeString(data.remainingBytes() / 2))
                                    .bearerOnly(data.consumeBoolean())
                                    .enforcerConfig(enforcerConfig)
                                    .credentialProvider(provider)
                                    .build();

      // Mock key method of the HttpServletRequest and HttpServletResponse with random data
      // Use the mock method to deny real HTTP request and simulate the response with random data
      Mockito.when(servletRequest.getParameter(data.consumeString(data.remainingBytes() / 2)))
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(servletResponse.getWriter())
          .thenReturn(new PrintWriter(data.consumeRemainingAsString()));

      // Fuzz the enforce method with the mocked object and random data
      enforcer.enforce(request, response);
    } catch (IOException | RuntimeException e) {
      // Known exception thrown directly from method above.
    } finally {
      // Suggest the java garbage collector to clean up unused memory
      System.gc();
    }
  }
}
