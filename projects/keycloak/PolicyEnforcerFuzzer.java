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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.EnumSet;
import java.util.Map;
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
 * This fuzzer targets the methods in the PolicyEnforcer
 * class of the authz package.
 */
public class PolicyEnforcerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Initialize enforcer config instance
      PolicyEnforcerConfig enforcerConfig = new PolicyEnforcerConfig();
      enforcerConfig.setEnforcementMode(
          data.pickValue(EnumSet.allOf(PolicyEnforcerConfig.EnforcementMode.class)));
      enforcerConfig.setOnDenyRedirectTo(data.consumeString(data.remainingBytes() / 2));
      enforcerConfig.setHttpMethodAsScope(data.consumeBoolean());
      enforcerConfig.setRealm(data.consumeString(data.remainingBytes() / 2));
      enforcerConfig.setAuthServerUrl(data.consumeString(data.remainingBytes() / 2));
      enforcerConfig.setResource(data.consumeString(data.remainingBytes() / 2));

      // Prepare credential map
      Map<String, Object> map = enforcerConfig.getCredentials();
      map.put(data.consumeString(data.remainingBytes() / 2),
          data.consumeString(data.remainingBytes() / 2));
      enforcerConfig.setCredentials(map);

      // Prepare client credentials provider
      ClientCredentialsProvider provider =
          ClientCredentialsProviderUtils.bootstrapClientAuthenticator(new AdapterConfig());

      PolicyEnforcer enforcer = PolicyEnforcer.builder()
                                    .clientId(data.consumeString(data.remainingBytes() / 2))
                                    .bearerOnly(data.consumeBoolean())
                                    .enforcerConfig(enforcerConfig)
                                    .credentialProvider(provider)
                                    .build();

      // Mock HttpServletRequest, HttpServletResponse and TokenPrincipal
      HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
      HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
      TokenPrincipal principal = Mockito.mock(TokenPrincipal.class);

      Mockito.when(servletRequest.getParameter(data.consumeString(data.remainingBytes() / 2)))
          .thenReturn(data.consumeString(data.remainingBytes() / 2));
      Mockito.when(servletResponse.getWriter())
          .thenReturn(new PrintWriter(data.consumeString(data.remainingBytes() / 2)));
      Mockito.when(principal.getToken()).thenReturn(new AccessToken());

      // Prepare ServletHttpRequest and ServletHttpResponse
      HttpRequest request = new ServletHttpRequest(servletRequest, principal);
      HttpResponse response = new ServletHttpResponse(servletResponse);

      enforcer.enforce(request, response);
    } catch (Exception e) {
      // Known exception thrown directly from method above.
    }
  }
}
