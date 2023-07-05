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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.keycloak.json.StringOrArrayDeserializer;
import org.keycloak.json.StringOrArraySerializer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class JsonSerializerDeserializationFuzzer implements Serializable {
  @JsonProperty("text")
  @JsonSerialize(using = StringOrArraySerializer.class)
  @JsonDeserialize(using = StringOrArrayDeserializer.class)
  protected String[] text;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer count = data.consumeInt(1, 10);
      String text = data.consumeRemainingAsString();
      String[] input = new String[count];
      for (int i=0; i < count; i++) {
        input[i] = text;
      }
      JsonSerializerDeserializationFuzzer target = new JsonSerializerDeserializationFuzzer();
      target.text = input;

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(target);

      ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
      ObjectInputStream ois = new ObjectInputStream(bais);
      ois.readObject();
    } catch (IOException | ClassNotFoundException e) {
      // Known exception
    }
  }
}
