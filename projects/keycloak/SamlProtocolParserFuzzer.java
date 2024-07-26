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
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.parsers.StaxParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLArtifactResolveParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLArtifactResponseParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLAttributeQueryParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLAuthNRequestParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLExtensionsParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLRequestedAuthnContextParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLResponseParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLSloRequestParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLSloResponseParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLStatusCodeParser;
import org.keycloak.saml.processing.core.parsers.saml.protocol.SAMLStatusParser;

/**
 * This fuzzer targets the parse method of all instances and implementation of StaxParser in
 * org.keycloak.saml.processing.core.parsers.saml.protocol package. It creates a XMLEventReader with
 * random bytes in UTF-8 encoding and pass it as a source for the a random SAML parser to parse it.
 */
public class SamlProtocolParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Initialise a StaxParser object
      StaxParser parser = null;

      // Retrieve or create a random SAML Parser object
      // instance and run the parse method with the
      // random data provided by the XMLEventReader
      // object created above
      switch (data.consumeInt(1, 11)) {
        case 1:
          parser = SAMLArtifactResolveParser.getInstance();
          break;
        case 2:
          parser = SAMLArtifactResponseParser.getInstance();
          break;
        case 3:
          parser = SAMLAttributeQueryParser.getInstance();
          break;
        case 4:
          parser = SAMLAuthNRequestParser.getInstance();
          break;
        case 5:
          parser = SAMLExtensionsParser.getInstance();
          break;
        case 6:
          parser = SAMLRequestedAuthnContextParser.getInstance();
          break;
        case 7:
          parser = SAMLResponseParser.getInstance();
          break;
        case 8:
          parser = SAMLSloRequestParser.getInstance();
          break;
        case 9:
          parser = SAMLSloResponseParser.getInstance();
          break;
        case 10:
          parser = SAMLStatusCodeParser.getInstance();
          break;
        case 11:
          parser = SAMLStatusParser.getInstance();
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
