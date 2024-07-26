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
import org.keycloak.jose.JOSEParser;

/**
 * This fuzzer targets the parse method of JOSEParser. It calls the JOSEParser.parse method with
 * random string to fuzz its parsing ability.
 */
public class JoseParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Call the JOSEParser.parse method with random
      // string generated from the FuzzedDataProvider
      JOSEParser.parse(data.consumeRemainingAsString());
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
