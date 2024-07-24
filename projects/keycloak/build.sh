#!/bin/bash -eu
# Copyright 2023 the cncf-fuzzing authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build Keycloak

## Maven build arguments
MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 "
MAVEN_ARGS=$MAVEN_ARGS"-DskipTests -Dgpg.skip -Dmaven.source.skip "
MAVEN_ARGS=$MAVEN_ARGS"-DskipExamples -DskipTestsuite -DskipQuarkus"

## Exclude unfuzzed modules
## This is needed to decrease the build time by excluding modules
## which are not used by the fuzzers.
EXCLUDE_DOCS="!docs,!docs/maven-plugin,!docs/guides"

EXCLUDE_DEPENDENCY="!dependencies/server-all"

EXCLUDE_FEDERATION="!federation,!federation/sssd"

EXCLUDE_INTEGRATION="!integration,!integration/admin-client-jee,!integration/admin-client,"
EXCLUDE_INTEGRATION=$EXCLUDE_INTEGRATION"!integration/client-registration,!integration/client-cli,"
EXCLUDE_INTEGRATION=$EXCLUDE_INTEGRATION"!integration/client-cli/admin-cli,!integration/client-cli/client-cli-dist"

EXCLUDE_JS="!js,!js/libs/keycloak-admin-client,!js/libs/keycloak-js"

EXCLUDE_MISC="!misc,!misc/keycloak-test-helper"

EXCLUDE_MODEL="!model/infinispan"

EXCLUDE_QUARKUS="!quarkus,!quarkus/config-api,!quarkus/runtime,!quarkus/deployment,"
EXCLUDE_QUARKUS=$EXCLUDE_QUARKUS"!quarkus/server,!quarkus/dist,!quarkus/tests,!quarkus/tests/junit5"

EXCLUDE_REST="!rest,!rest/admin-ui-ext"

EXCLUDE_MODULE=$EXCLUDE_DOCS,$EXCLUDE_DEPENDENCY,$EXCLUDE_FEDERATION,$EXCLUDE_INTEGRATION,$EXCLUDE_JS
EXCLUDE_MODULE=$EXCLUDE_MODULE,$EXCLUDE_MISC,$EXCLUDE_MODEL,$EXCLUDE_QUARKUS,$EXCLUDE_REST

## Execute maven build
$MVN clean package dependency:copy-dependencies -pl "$EXCLUDE_MODULE" $MAVEN_ARGS

# Dependency for Mockito and MockWebService functionality for mocking objects and web service
mkdir -p fuzzer-dependencies
wget https://repo1.maven.org/maven2/org/mockito/mockito-core/5.4.0/mockito-core-5.4.0.jar -O fuzzer-dependencies/mockito-core.jar
wget https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy-agent/1.14.5/byte-buddy-agent-1.14.5.jar -O fuzzer-dependencies/byte-buddy-agent.jar
wget https://repo1.maven.org/maven2/com/squareup/okhttp3/mockwebserver/4.11.0/mockwebserver-4.11.0.jar -O fuzzer-dependencies/mockwebserver.jar
wget https://repo1.maven.org/maven2/com/squareup/okio/okio/3.2.0/okio-3.2.0.jar -O fuzzer-dependencies/okio.jar
wget https://repo1.maven.org/maven2/com/squareup/okio/okio-jvm/3.2.0/okio-jvm-3.2.0.jar -O fuzzer-dependencies/okio-jvm.jar
wget https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.11.0/okhttp-4.11.0.jar -O fuzzer-dependencies/okhttp.jar
wget https://repo1.maven.org/maven2/junit/junit/4.13/junit-4.13.jar -O fuzzer-dependencies/junit.jar
wget https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib-common/1.6.10/kotlin-stdlib-common-1.6.10.jar -O fuzzer-dependencies/kotlin-stdlib-commin.jar
wget https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.6.10/kotlin-stdlib-1.6.10.jar -O fuzzer-dependencies/kotlin-stdlib.jar

RUNTIME_CLASSPATH=

for JARFILE in $(find . -wholename "*/target/keycloak*.jar")
do
  if [[ "$JARFILE" == *"authz/"* ]] || [[ "$JARFILE" == *"common/"* ]] || \
  [[ "$JARFILE" == *"core/"* ]] || [[ "$JARFILE" == *"crypto/"* ]] || \
  [[ "$JARFILE" == *"model/"* ]] || [[ "$JARFILE" == *"saml-core/"* ]] || \
  [[ "$JARFILE" == *"saml-core-api/"* ]] || [[ "$JARFILE" == *"services/"* ]] || \
  [[ "$JARFILE" == *"server-spi-private/"* ]] || [[ "$JARFILE" == *"server-spi/"* ]]
  then
    cp $JARFILE $OUT/
    RUNTIME_CLASSPATH=$RUNTIME_CLASSPATH\$this_dir/$(basename $JARFILE):
  fi
done

# Copy keycloak dependencies
for JARFILE in $(find . -wholename "*/target/dependency/*.jar" ! -name keycloak*.jar)
do
  cp $JARFILE fuzzer-dependencies/
done
mkdir -p $OUT/fuzzer-dependencies
unzip -o fuzzer-dependencies/\*.jar -d $OUT/fuzzer-dependencies/

BUILD_CLASSPATH=$OUT/*:$SRC/keycloak/fuzzer-dependencies/*:$JAZZER_API_PATH
RUNTIME_CLASSPATH=$RUNTIME_CLASSPATH:\$this_dir:\$this_dir/fuzzer-dependencies

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  $JAVA_HOME/bin/javac -cp $BUILD_CLASSPATH:$SRC -d $SRC/ $fuzzer
  cp $SRC/$fuzzer_basename*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi

apt install openjdk-17-jdk -y

export JAVA_HOME=\"/usr/lib/jvm/java-17-openjdk-amd64\"
export LD_LIBRARY_PATH=\"\$JAVA_HOME/lib/server\":\$this_dir
export PATH=\$JAVA_HOME/bin:\$PATH

CURRENT_JAVA_VERSION=\$(java --version | head -n1)

if [[ \"\$CURRENT_JAVA_VERSION\" != \"openjdk 17\"* ]]
then
  echo Requires JDK-17+, found \$CURRENT_JAVA_VERSION
  exit -1
fi

\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done

# Remove executable for abstract BaseKeycloakSessionFuzzer
rm $OUT/BaseKeycloakSessionFuzzer

zip $OUT/SamlParserFuzzer_seed_corpus.zip $SRC/cncf-fuzzing/projects/keycloak/seeds/SamlParserFuzzer_seed_*
zip $OUT/JwkParserFuzzer_seed_corpus.zip $SRC/cncf-fuzzing/projects/keycloak/seeds/JwkParserFuzzer_seed_1
zip $OUT/JoseParserFuzzer_seed_corpus.zip $SRC/cncf-fuzzing/projects/keycloak/seeds/json.seed
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlAssertionParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlConfigParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlMetadataParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlProtocolParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlProcessingUtilFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlValidationUtilFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/saml.dict $OUT/SamlXmlUtilFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/json.dict $OUT/JwkParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/json.dict $OUT/JoseParserFuzzer.dict
