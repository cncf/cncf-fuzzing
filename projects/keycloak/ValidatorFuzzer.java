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

      // Generate random map for ValidatorConfig
      Map<String, Object> configMap = new HashMap<String, Object>();
      for (int i = 0; i < data.consumeInt(0, 5); i++) {
        configMap.put(data.consumeString(10), data.consumeString(10));
      }
      ValidatorConfig config = new ValidatorConfig(configMap);

      switch (data.consumeInt(1, 12)) {
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

      if (data.consumeBoolean()) {
        validator.validate(data.consumeRemainingAsString(), "Hint", context, config);
      } else {
        validator.validate(data.consumeRemainingAsBytes(), "Hint", context, config);
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
