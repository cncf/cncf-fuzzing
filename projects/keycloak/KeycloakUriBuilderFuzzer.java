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
      String string = data.consumeString(data.consumeInt(0, 10000));

      // Fuzz static methods
      switch (data.consumeInt(1, 6)) {
        case 1:
      	  KeycloakUriBuilder.fromUri(new URI(string));
	case 2:
	  KeycloakUriBuilder.fromUri(string);
	case 3:
	  KeycloakUriBuilder.fromPath(string);
	case 4:
	  KeycloakUriBuilder.fromTemplate(string);
	case 5:
	  KeycloakUriBuilder.compare(string, string);
	case 6:
	  KeycloakUriBuilder.relativize(new URI(string), new URI(string));
      }

      // Create and configure KeycloakUriBuilder object
      KeycloakUriBuilder builder = new KeycloakUriBuilder();
      String string2 = data.consumeRemainingAsString();
      switch (data.consumeInt(1, 6)) {
        case 1:
          builder = builder.schemeSpecificPart(string2);
	case 2:
	  builder = builder.userInfo(string2);
	case 3:
	  builder = builder.host(string2);
	case 4:
	  builder = builder.replaceMatrix(string2);
	case 5:
	  builder = builder.replaceQuery(string2);
	case 6:
	  builder = builder.fragment(string2);
      }

      // Call build to build the target URI
      builder.build(data.consumeString(data.consumeInt(0, 10000)),
		    data.consumeString(data.consumeInt(0, 10000)),
		    data.consumeString(data.consumeInt(0, 10000)));
    } catch (URISyntaxException | RuntimeException e) {
      // Known exception
    }
  }
}
