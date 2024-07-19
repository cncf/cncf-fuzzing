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
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.parsers.AnyDomParser;
import org.keycloak.saml.common.parsers.StaxParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11AssertionParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11RequestParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11ResponseParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11SubjectParser;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.parsers.saml.xmldsig.DsaKeyValueParser;
import org.keycloak.saml.processing.core.parsers.saml.xmldsig.KeyInfoParser;
import org.keycloak.saml.processing.core.parsers.saml.xmldsig.RsaKeyValueParser;
import org.keycloak.saml.processing.core.parsers.saml.xmldsig.X509DataParser;

/**
 * This fuzzer targets the parse method of all StaxParser implementations. It creates a
 * XMLEventReader with random bytes in UTF-8 encoding and pass it as a source for the a random SAML
 * parser to parse it.
 */
public class SamlParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Initialise StaxParser object
      StaxParser parser = null;

      // Retrieve or create a random SAML Parser object
      // instance and run the parse method with the
      // random data provided by the XMLEventReader
      // object created above
      switch (data.consumeInt(1, 10)) {
        case 1:
          parser = SAMLParser.getInstance();
          break;
        case 2:
          parser = new SAML11SubjectParser();
          break;
        case 3:
          parser = new SAML11ResponseParser();
          break;
        case 4:
          parser = new SAML11RequestParser();
          break;
        case 5:
          parser = new SAML11AssertionParser();
          break;
        case 6:
          QName qName = new QName(data.consumeString(data.consumeInt(1, 1024)));
          parser = AnyDomParser.getInstance(qName);
          break;
        case 7:
          parser = DsaKeyValueParser.getInstance();
          break;
        case 8:
          parser = KeyInfoParser.getInstance();
          break;
        case 9:
          parser = RsaKeyValueParser.getInstance();
          break;
        case 10:
          parser = X509DataParser.getInstance();
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
