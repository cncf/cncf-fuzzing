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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.keycloak.json.StringListMapDeserializer;
import org.keycloak.json.StringOrArrayDeserializer;
import org.keycloak.json.StringOrArraySerializer;

/**
 * This fuzzer targets the serialize method of the StringOrArraySerializer class and the deserialize
 * method of the StringOrArrayDeserializer / StringListMapDeserializer class. The fuzzer class
 * contains three different nested static class with a map / string / string array parameter. Those
 * parameters are used for fuzzing the serializing and deserializing of differet Serializer and
 * Deserializer in the keycloak json package. The specification is done by using the Jackson
 * databind annotation classes.
 */
public class JsonSerializerDeserializerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      ObjectMapper mapper = new ObjectMapper();

      switch (data.consumeInt(1, 5)) {
        case 1:
          mapper.readValue(data.consumeRemainingAsString(), TestMapObject.class);
          break;
        case 2:
          mapper.readValue(data.consumeRemainingAsString(), TestStringObject.class);
          break;
        case 3:
          mapper.readValue(data.consumeRemainingAsString(), TestArrayObject.class);
          break;
        case 4:
          TestStringObject testStringObject =
              new JsonSerializerDeserializerFuzzer.TestStringObject(
                  data.consumeRemainingAsString());
          mapper.writeValueAsString(testStringObject);
          break;
        case 5:
          TestArrayObject testArrayObject =
              new JsonSerializerDeserializerFuzzer.TestArrayObject(data);
          mapper.writeValueAsString(testArrayObject);
          break;
      }
    } catch (IOException e) {
      // Known exception
    }
  }

  private static class TestMapObject {
    @JsonDeserialize(using = StringListMapDeserializer.class)
    private final Map<String, List<String>> map = null;

    public Map<String, List<String>> getMap() {
      return this.map;
    }
  }

  private static class TestStringObject {
    @JsonSerialize(using = StringOrArraySerializer.class)
    @JsonDeserialize(using = StringOrArrayDeserializer.class)
    private String text;

    public TestStringObject(String text) {
      this.text = text;
    }

    public String getText(String text) {
      return this.text;
    }
  }

  private static class TestArrayObject {
    @JsonSerialize(using = StringOrArraySerializer.class)
    @JsonDeserialize(using = StringOrArrayDeserializer.class)
    private String[] array;

    public TestArrayObject(FuzzedDataProvider data) {
      Integer count = data.consumeInt(1, 10);
      String text = data.consumeRemainingAsString();
      this.array = new String[count];
      for (int i = 0; i < count; i++) {
        this.array[i] = text;
      }
    }

    public String[] getArray() {
      return this.array;
    }
  }
}
