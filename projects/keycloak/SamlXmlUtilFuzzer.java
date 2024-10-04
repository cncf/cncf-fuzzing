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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Consumer;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.encryption.EncryptedData;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * This fuzzer targets methods in XMLEncryptionUtil and XmlSignatureUtil classes of the
 * org.keycloak.saml.processing.core.util package. It passes random data to fuzz all those static
 * utils methods.
 */
public class SamlXmlUtilFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // InitialiseKeycloakSession
      BaseHelper.createKeycloakSession(data);

      // Create document object
      Document doc = null;

      // Initialise a random XML Document object
      DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
      doc = builder.parse("<saml_sample></saml_sample>");

      // Generate a keypair
      SecureRandom random = new SecureRandom(data.consumeBytes(2500));
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(32, random);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
      keyGenerator.init(32, random);
      SecretKey secretKey = keyGenerator.generateKey();

      switch (data.consumeInt(1, 5)) {
        case 1:
          // Initialise qname arguments
          QName elementName = new QName(data.consumeString(data.consumeInt(1, 32)));
          QName wrappingName = new QName(data.consumeString(data.consumeInt(1, 32)));

          // Initialise keys
          PublicKey pubKey = keyPair.getPublic();

          // Fuzz
          XMLEncryptionUtil.encryptElement(elementName, doc, pubKey, secretKey, 32, wrappingName, true);
          break;
        case 2:
          // Initialise DecryptionKeyLocator
          DefaultDecryptionKeyLocator locator =
              new DefaultDecryptionKeyLocator(keyPair.getPrivate());

          // Fuzz
          XMLEncryptionUtil.decryptElementInDocument(doc, locator);
          break;
        case 3:
          // Initialise string
          String referenceUri = data.consumeString(10);
          String type = data.consumeString(10);

          XMLSignatureUtil.sign(doc, "keyName", keyPair, "SHA1", "RSA_SHA1", referenceUri, type);
          break;
        case 4:
          // Initialise DefaultKeyLocator
          DefaultKeyLocator keyLocator =
              new DefaultKeyLocator(secretKey);

          XMLSignatureUtil.validate(doc, keyLocator);
          XMLSignatureUtil.validateSingleNode(doc, keyLocator);
          break;
        case 5:
          XMLSignatureUtil.createKeyValue(keyPair.getPublic());
          break;
      }
      System.out.println("ABC");
    } catch (ProcessingException
        | IOException
        | ParserConfigurationException
        | SAXException e) {
      // Known exception
    } catch (GeneralSecurityException | MarshalException | XMLSignatureException e) {
      // Known exception
    } finally {
      BaseHelper.cleanMockObject();
    }
  }

  private static class DefaultDecryptionKeyLocator
      implements XMLEncryptionUtil.DecryptionKeyLocator {
    private List<PrivateKey> keys;

    public DefaultDecryptionKeyLocator(PrivateKey key) {
      keys = new ArrayList<PrivateKey>();
      keys.add(key);
    }

    public List<PrivateKey> getKeys(EncryptedData encryptedData) {
      return keys;
    }
  }

  private static class DefaultKeyLocator implements KeyLocator {
    private Key key;

    public DefaultKeyLocator(Key key) {
      this.key = key;
    }

    public Key getKey(String kid) throws KeyManagementException {
      return this.key;
    }

    public void refreshKeyCache() {
      // Do nothing
    }

    public Iterator<Key> iterator() {
      List<Key> keyList = new ArrayList<Key>();
      keyList.add(key);

      return keyList.iterator();
    }

    public Spliterator<Key> spliterator() {
      List<Key> keyList = new ArrayList<Key>();
      keyList.add(key);

      return keyList.spliterator();
    }

    public void forEach(Consumer<? super Key> action) {
      // Do nothing
    }
  }
}
