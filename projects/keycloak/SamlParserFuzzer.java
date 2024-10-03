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
import org.keycloak.saml.common.parsers.AnyDomParser;
import org.keycloak.saml.common.parsers.StaxParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11AssertionParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11RequestParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11ResponseParser;
import org.keycloak.saml.processing.core.parsers.saml.SAML11SubjectParser;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAssertionParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAttributeParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAttributeStatementParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAttributeValueParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAudienceRestrictionParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAuthnContextParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAuthnStatementParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLConditionsParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLEncryptedAssertionParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLProxyRestrictionParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLSubjectConfirmationDataParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLSubjectConfirmationParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLSubjectParser;
import org.keycloak.saml.processing.core.parsers.saml.mdattr.SAMLEntityAttributesParser;
import org.keycloak.saml.processing.core.parsers.saml.mdui.SAMLUIInfoParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLArtifactResolutionServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAssertinIDRequestServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAssertionConsumerServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeAuthorityDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeConsumingServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAuthnAuthorityDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAuthnQueryServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAuthzServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLContactPersonParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLEncryptionMethodParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLEntityDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLExtensionsParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLIDPSSODescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLKeyDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLManageNameIDServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLNameIDMappingServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLOrganizationParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLPDPDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLRequestedAttributeParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLSPSSODescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLSingleLogoutServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLSingleSignOnServiceParser;
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
        case 14:
          QName qName = new QName(data.consumeString(data.consumeInt(1, 1024)));
          parser = AnyDomParser.getInstance(qName);
          break;
        case 15:
          parser = SAMLParser.getInstance();
          break;
        case 16:
          parser = new SAML11SubjectParser();
          break;
        case 17:
          parser = new SAML11ResponseParser();
          break;
        case 18:
          parser = new SAML11RequestParser();
          break;
        case 19:
          parser = new SAML11AssertionParser();
          break;
        case 20:
          parser = SAMLAssertionParser.getInstance();
          break;
        case 21:
          parser = SAMLAttributeParser.getInstance();
          break;
        case 22:
          parser = SAMLAttributeStatementParser.getInstance();
          break;
        case 23:
          parser = SAMLAttributeValueParser.getInstance();
          break;
        case 24:
          parser = SAMLAudienceRestrictionParser.getInstance();
          break;
        case 25:
          parser = SAMLAuthnContextParser.getInstance();
          break;
        case 26:
          parser = SAMLAuthnStatementParser.getInstance();
          break;
        case 27:
          parser = SAMLConditionsParser.getInstance();
          break;
        case 28:
          parser = SAMLEncryptedAssertionParser.getInstance();
          break;
        case 29:
          parser = SAMLProxyRestrictionParser.getInstance();
          break;
        case 30:
          parser = SAMLSubjectConfirmationDataParser.INSTANCE;
          break;
        case 31:
          parser = SAMLSubjectConfirmationParser.INSTANCE;
          break;
        case 32:
          parser = SAMLSubjectParser.getInstance();
          break;
        case 33:
          parser = SAMLEntityAttributesParser.getInstance();
          break;
        case 34:
          parser = SAMLUIInfoParser.getInstance();
          break;
        case 35:
          parser = SAMLArtifactResolutionServiceParser.getInstance();
          break;
        case 36:
          parser = SAMLAssertinIDRequestServiceParser.getInstance();
          break;
        case 37:
          parser = SAMLAssertionConsumerServiceParser.getInstance();
          break;
        case 38:
          parser = SAMLAttributeAuthorityDescriptorParser.getInstance();
          break;
        case 39:
          parser = SAMLAttributeConsumingServiceParser.getInstance();
          break;
        case 40:
          parser = SAMLAttributeParser.getInstance();
          break;
        case 41:
          parser = SAMLAttributeServiceParser.getInstance();
          break;
        case 42:
          parser = SAMLAuthnAuthorityDescriptorParser.getInstance();
          break;
        case 43:
          parser = SAMLAuthnQueryServiceParser.getInstance();
          break;
        case 44:
          parser = SAMLAuthzServiceParser.getInstance();
          break;
        case 45:
          parser = SAMLContactPersonParser.getInstance();
          break;
        case 46:
          parser = SAMLEncryptionMethodParser.getInstance();
          break;
        case 47:
          parser = SAMLEntityDescriptorParser.getInstance();
          break;
        case 48:
          parser = SAMLExtensionsParser.getInstance();
          break;
        case 49:
          parser = SAMLIDPSSODescriptorParser.getInstance();
          break;
        case 50:
          parser = SAMLKeyDescriptorParser.getInstance();
          break;
        case 51:
          parser = SAMLManageNameIDServiceParser.getInstance();
          break;
        case 52:
          parser = SAMLNameIDMappingServiceParser.getInstance();
          break;
        case 53:
          parser = SAMLOrganizationParser.getInstance();
          break;
        case 54:
          parser = SAMLPDPDescriptorParser.getInstance();
          break;
        case 55:
          parser = SAMLRequestedAttributeParser.getInstance();
          break;
        case 56:
          parser = SAMLSingleLogoutServiceParser.getInstance();
          break;
        case 57:
          parser = SAMLSingleSignOnServiceParser.getInstance();
          break;
        case 58:
          parser = SAMLSPSSODescriptorParser.getInstance();
          break;
        case 59:
          parser = SAMLArtifactResolveParser.getInstance();
          break;
        case 60:
          parser = SAMLArtifactResponseParser.getInstance();
          break;
        case 61:
          parser = SAMLAttributeQueryParser.getInstance();
          break;
        case 62:
          parser = SAMLAuthNRequestParser.getInstance();
          break;
        case 63:
          parser = SAMLExtensionsParser.getInstance();
          break;
        case 64:
          parser = SAMLRequestedAuthnContextParser.getInstance();
          break;
        case 65:
          parser = SAMLResponseParser.getInstance();
          break;
        case 66:
          parser = SAMLSloRequestParser.getInstance();
          break;
        case 67:
          parser = SAMLSloResponseParser.getInstance();
          break;
        case 68:
          parser = SAMLStatusCodeParser.getInstance();
          break;
        case 69:
          parser = SAMLStatusParser.getInstance();
          break;
        case 70:
          parser = DsaKeyValueParser.getInstance();
          break;
        case 71:
          parser = KeyInfoParser.getInstance();
          break;
        case 72:
          parser = RsaKeyValueParser.getInstance();
          break;
        case 73:
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
