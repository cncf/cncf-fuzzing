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
import java.net.URI;
import java.net.URISyntaxException;
import org.keycloak.common.util.KeycloakUriBuilder;

/** This fuzzer targets the methods in the KeycloakUriBuilder class. */
public class KeycloakUriBuilderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Generate random data
      String string = data.consumeRemainingAsString();

      // Fuzz static methods
      KeycloakUriBuilder.fromUri(new URI(string));
      KeycloakUriBuilder.fromUri(string);
      KeycloakUriBuilder.fromPath(string);
      KeycloakUriBuilder.fromTemplate(string);
      KeycloakUriBuilder.compare(string, string);
      KeycloakUriBuilder.relativize(new URI(string), new URI(string));

      // Create and configure KeycloakUriBuilder object
      KeycloakUriBuilder builder = new KeycloakUriBuilder();
      builder = builder.schemeSpecificPart(string);
      builder = builder.userInfo(string);
      builder = builder.host(string);
      builder = builder.replaceMatrix(string);
      builder = builder.replaceQuery(string);
      builder = builder.fragment(string);

      // Call build to build the target URI
      builder.build(string, string, string);
    } catch (URISyntaxException | RuntimeException e) {
      // Known exception
    }
  }
}
