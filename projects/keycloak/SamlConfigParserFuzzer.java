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
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import org.keycloak.adapters.saml.config.parsers.HttpClientParser;
import org.keycloak.adapters.saml.config.parsers.IdpParser;
import org.keycloak.adapters.saml.config.parsers.KeyParser;
import org.keycloak.adapters.saml.config.parsers.KeyStoreParser;
import org.keycloak.adapters.saml.config.parsers.KeycloakSamlAdapterParser;
import org.keycloak.adapters.saml.config.parsers.KeycloakSamlAdapterV1Parser;
import org.keycloak.adapters.saml.config.parsers.KeysParser;
import org.keycloak.adapters.saml.config.parsers.PrincipalNameMappingParser;
import org.keycloak.adapters.saml.config.parsers.RoleMappingParser;
import org.keycloak.adapters.saml.config.parsers.RoleMappingsProviderParser;
import org.keycloak.adapters.saml.config.parsers.SingleLogoutServiceParser;
import org.keycloak.adapters.saml.config.parsers.SingleSignOnServiceParser;
import org.keycloak.adapters.saml.config.parsers.SpParser;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.parsers.StaxParser;

/**
 * This fuzzer targets the parse method of all instances and implementation of StaxParser in
 * org.keycloak.adapters.saml.config.parsers package. It creates a XMLEventReader with random bytes
 * in UTF-8 encoding and pass it as a source for the a random SAML parser to parse it.
 */
public class SamlConfigParserFuzzer extends BaseFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Initialise a StaxParser object
      StaxParser parser = null;

      // Retrieve or create a random SAML Parser object
      // instance and run the parse method with the
      // random data provided by the XMLEventReader
      // object created above
      switch (data.consumeInt(1, 13)) {
        case 1:
          parser = HttpClientParser.getInstance();
          break;
        case 2:
          parser = IdpParser.getInstance();
          break;
        case 3:
          parser = KeycloakSamlAdapterParser.getInstance();
          break;
        case 4:
          parser = KeycloakSamlAdapterV1Parser.getInstance();
          break;
        case 5:
          parser = KeysParser.getInstance();
          break;
        case 6:
          parser = KeyParser.getInstance();
          break;
        case 7:
          parser = KeyStoreParser.getInstance();
          break;
        case 8:
          parser = PrincipalNameMappingParser.getInstance();
          break;
        case 9:
          parser = RoleMappingsProviderParser.getInstance();
          break;
        case 10:
          parser = RoleMappingParser.getInstance();
          break;
        case 11:
          parser = SingleLogoutServiceParser.getInstance();
          break;
        case 12:
          parser = SingleSignOnServiceParser.getInstance();
          break;
        case 13:
          parser = SpParser.getInstance();
          break;
      }

      // Initialize a XMLEventReader with InputStream source pointing
      // to a random byte array in UTF-8 encoding retrieved from the
      // FuzzedDataProvider
      byte[] input = data.consumeRemainingAsString().getBytes(StandardCharsets.UTF_8);
      ByteArrayInputStream bais = new ByteArrayInputStream(input);
      XMLEventReader reader = XMLInputFactory.newInstance().createXMLEventReader(bais);

      if (parser != null) {
        parser.parse(reader);
      }
    } catch (ParsingException | XMLStreamException | RuntimeException e) {
      // Known exception
    }
  }
}
