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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.BiPredicate;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.keycloak.authorization.client.AuthzClient;

/**
 * This fuzzer creates the keycloakJson configuration
 * settings and fuzz the protection and authorization
 * methods in the AuthzClient
 */
public class AuthzClientFuzzer extends BaseFuzzer {
  // Template string for the keycloak json
  // Temporary set to empty url, will point
  // to a mock server when it is implemented
  private static final String keycloakJson =
      "{\"realm\":\"oss-fuzz\",\"realm-public-key\":\"TESTING_KEY\",\"auth-server-url\":\"SERVER_URL\",\"ssl-required\":\"internal\",\"resource\":\"connect\",\"public-client\":false}";
  private static MockWebServer server;
  private static String serverUrl;

  public static void fuzzerInitialize() {
    // Prepare MockWebServer
    try {
      // Start the mock web server
      server = new MockWebServer();
      server.start();

      // Retrieve host name and port of the mock web server
      String serverHost = server.getHostName();
      Integer serverPort = server.getPort();

      // Mock web server url
      serverUrl = "http://" + serverHost + ":" + serverPort;

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
      MockResponse mockResponse = new MockResponse();
      mockResponse.setBody(generateServerConfigurationJson());
      mockResponse.addHeader("Content-Type", "application/json");
      server.enqueue(mockResponse);

      // Set the auth-url to the mock web server
      String jsonString = keycloakJson.replace("SERVER_URL", serverUrl);

      // Create the authz client object for fuzzing
      AuthzClient client =
          AuthzClient.create(new ByteArrayInputStream(jsonString.getBytes(StandardCharsets.UTF_8)));

      // Randomly fuzz different version of the protection and authorization methods
      // with different parameter combinations
      switch (data.consumeInt(1, 5)) {
        case 1:
          client.protection(data.consumeRemainingAsString());
          break;
        case 2:
          client.protection(
              data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
          break;
        case 3:
          client.authorization(data.consumeRemainingAsString());
          break;
        case 4:
          client.authorization(data.consumeString(data.remainingBytes() / 2),
              data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
          break;
        case 5:
          client.obtainAccessToken(
              data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
          break;
      }
    } catch (RuntimeException e) {
      // Known exception thrown directly from method above.
    }
  }
}
