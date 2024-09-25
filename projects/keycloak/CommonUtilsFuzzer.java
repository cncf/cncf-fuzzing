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
import java.net.InetSocketAddress;
import org.keycloak.common.util.Encode;
import org.keycloak.common.util.EnvUtil;
import org.keycloak.common.util.FindFile;
import org.keycloak.common.util.HtmlUtils;
import org.keycloak.common.util.NetworkUtils;
import org.keycloak.common.util.PathHelper;
import org.keycloak.common.util.StackUtil;

/** This fuzzer targets the methods in different util classes in the common package. */
public class CommonUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomly choose which utils method to invoke
      Integer choice = data.consumeInt(1, 21);
      switch (choice) {
        case 1:
          Encode.encodeQueryString(data.consumeRemainingAsString());
        case 2:
          Encode.encodePath(data.consumeRemainingAsString());
        case 3:
          Encode.encodePathSegment(data.consumeRemainingAsString());
        case 4:
          Encode.encodeFragment(data.consumeRemainingAsString());
        case 5:
          Encode.encodeMatrixParam(data.consumeRemainingAsString());
        case 6:
          Encode.encodeQueryParam(data.consumeRemainingAsString());
        case 7:
          Encode.decodePath(data.consumeRemainingAsString());
        case 8:
          Encode.encodePathAsIs(data.consumeRemainingAsString());
        case 9:
          Encode.encodePathSaveEncodings(data.consumeRemainingAsString());
        case 10:
          Encode.encodePathSegmentAsIs(data.consumeRemainingAsString());
        case 11:
          Encode.encodePathSegmentSaveEncodings(data.consumeRemainingAsString());
        case 12:
          Encode.encodeQueryParamAsIs(data.consumeRemainingAsString());
        case 13:
          Encode.encodeQueryParamSaveEncodings(data.consumeRemainingAsString());
        case 14:
          Encode.encodeFragmentAsIs(data.consumeRemainingAsString());
        case 15:
          EnvUtil.replace(data.consumeRemainingAsString());
        case 16:
          FindFile.findFile(data.consumeRemainingAsString());
        case 17:
          HtmlUtils.escapeAttribute(data.consumeRemainingAsString());
        case 18:
          Integer port = data.consumeInt(1, 65536);
          NetworkUtils.formatAddress(new InetSocketAddress(data.consumeRemainingAsString(), port));
        case 19:
          PathHelper.replaceEnclosedCurlyBraces(data.consumeRemainingAsString());
        case 20:
          PathHelper.recoverEnclosedCurlyBraces(data.consumeRemainingAsString());
        case 21:
          StackUtil.getShortStackTrace(data.consumeRemainingAsString());
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
