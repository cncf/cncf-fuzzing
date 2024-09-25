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
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.util.List;
import org.keycloak.saml.processing.core.util.JAXBUtil;
import org.keycloak.saml.processing.core.util.SchemaManagerUtil;
import org.xml.sax.SAXException;

/**
 * This fuzzer targets static methods in JAXBUtil class of the
 * org.keycloak.saml.processing.core.util package. It passes random data to fuzz all those static
 * utils methods.
 */
public class SamlProcessingUtilFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Retrieve list of schemas
      List<String> schemas = SchemaManagerUtil.getSchemas();

      // Pick a schema
      String schema = data.pickValue(schemas);

      // Pick a choice
      Integer choice = data.consumeInt(1, 4);

      // Pick a package name
      String name = data.consumeRemainingAsString();

      // Match random package name to each schma
      String[] names = new String[schemas.size()];
      for (int i = 0; i < names.length; i++) {
        names[i] = name;
      }

      switch (choice) {
        case 1:
          JAXBUtil.getValidatingMarshaller(name, schema);
        case 2:
          JAXBUtil.getMarshaller(name);
        case 3:
          JAXBUtil.getUnmarshaller(name);
        case 4:
          String[] schemaArray = (String[]) schemas.toArray();
          JAXBUtil.getValidatingUnmarshaller(names, schemaArray);
      }
    } catch (JAXBException | RuntimeException | SAXException | IOException e) {
      // Known exception
    }
  }
}
