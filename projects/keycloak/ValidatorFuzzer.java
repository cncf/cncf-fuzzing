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
import java.util.HashMap;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.validate.BuiltinValidators;
import org.keycloak.validate.SimpleValidator;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidatorConfig;

/** This fuzzer targets different validator instances of the keycloak project. */
public class ValidatorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      SimpleValidator validator = null;
      KeycloakSession session = BaseHelper.createKeycloakSession(data);
      ValidationContext context = new ValidationContext(session);

      Integer choice = data.consumeInt(1, 12);
      Integer choice2 = data.consumeInt(1, 14);

      // Generate random map for ValidatorConfig
      Map<String, Object> configMap = new HashMap<String, Object>();
      for (int i = 0; i < data.consumeInt(0, 5); i++) {
        configMap.put(data.consumeString(data.consumeInt(0, 10)), data.consumeString(data.consumeInt(0, 10)));
      }
      ValidatorConfig config = new ValidatorConfig(configMap);

      switch (choice) {
        case 1:
          validator = BuiltinValidators.notBlankValidator();
          break;
        case 2:
          validator = BuiltinValidators.notEmptyValidator();
          break;
        case 3:
          validator = BuiltinValidators.lengthValidator();
          break;
        case 4:
          validator = BuiltinValidators.uriValidator();
          break;
        case 5:
          validator = BuiltinValidators.emailValidator();
          break;
        case 6:
          validator = BuiltinValidators.patternValidator();
          break;
        case 7:
          validator = BuiltinValidators.doubleValidator();
          break;
        case 8:
          validator = BuiltinValidators.integerValidator();
          break;
        case 9:
          validator = BuiltinValidators.dateValidator();
          break;
        case 10:
          validator = BuiltinValidators.isoDateValidator();
          break;
        case 11:
          validator = BuiltinValidators.optionsValidator();
          break;
        case 12:
          validator = BuiltinValidators.validatorConfigValidator();
          break;
      }

      Object obj = null;
      switch(choice2) {
        case 1: obj = data.consumeBoolean(); break;
        case 2: obj = data.consumeBooleans(5); break;
        case 3: obj = data.consumeByte(); break;
        case 4: obj = data.consumeRemainingAsBytes(); break;
        case 5: obj = data.consumeShort(); break;
        case 6: obj = data.consumeShorts(5); break;
        case 7: obj = data.consumeInt(); break;
        case 8: obj = data.consumeInts(5); break;
        case 9: obj = data.consumeLong(); break;
        case 10: obj = data.consumeLongs(5); break;
        case 11: obj = data.consumeFloat(); break;
        case 12: obj = data.consumeDouble(); break;
        case 13: obj = data.consumeChar(); break;
        case 14: obj = data.consumeRemainingAsString(); break;
      }
      validator.validate(obj, "Hint", context, config);
    } catch (RuntimeException e) {
      // Known exception
      throw e;
    } finally {
      BaseHelper.cleanMockObject();
    }
  }
}
