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
import java.security.Key;
import java.security.KeyManagementException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.function.Consumer;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.util.JAXPValidationUtil;
import org.keycloak.saml.processing.core.util.RedirectBindingSignatureUtil;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * This fuzzer targets static methods in RedirectBindingSignatureUtil and JAXPValidationUtil classes
 * of the org.keycloak.saml.processing.core.util package. It passes random data to fuzz all those
 * static utils methods.
 */
public class SamlValidationUtilFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Retrieve all saml signature algorithm
      EnumSet<SignatureAlgorithm> sigAlgs = EnumSet.allOf(SignatureAlgorithm.class);

      switch (data.consumeInt(1, 3)) {
        case 1:
          // Pick a signature algorithm
          SignatureAlgorithm sigAlg = data.pickValue(sigAlgs);

          // Initialise DefaultKeyLocator
          DefaultKeyLocator keyLocator =
              new DefaultKeyLocator(KeyUtils.loadSecretKey(data.consumeBytes(32), "HmacSHA256"));

          // Initialise Signature
          byte[] signature = data.consumeBytes(32);

          // Initialise raw query bytes
          byte[] rawBytes = data.consumeRemainingAsBytes();

          // Fuzz
          RedirectBindingSignatureUtil.validateRedirectBindingSignature(
              sigAlg, rawBytes, signature, keyLocator, "Fuzz");
        case 2:
          JAXPValidationUtil.validate(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
        case 3:
          // Initialise a random XML Document object
          DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();

          // Create document object
          Document doc = builder.parse(new ByteArrayInputStream(data.consumeRemainingAsBytes()));

          JAXPValidationUtil.checkSchemaValidation(doc);
      }
    } catch (RuntimeException | IOException | SAXException | ProcessingException e) {
      // Known exception
    } catch (KeyManagementException | VerificationException | ParserConfigurationException e) {
      // Known exception
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
