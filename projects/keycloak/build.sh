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

# Retrieve JDK-17
#wget https://download.java.net/openjdk/jdk17/ri/openjdk-17+35_linux-x64_bin.tar.gz
#tar -zxf openjdk-17+35_linux-x64_bin.tar.gz
#cp -r jdk-17 $OUT/
JAVA_HOME=$OUT/jdk-17
PATH=$JAVA_HOME/bin:$PATH

# Build Keycloak
#MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 "
#MAVEN_ARGS=$MAVEN_ARGS"-DskipTests -Dgpg.skip -Dmaven.source.skip "
#MAVEN_ARGS=$MAVEN_ARGS"-DskipExamples -DskipTestsuite"
#$MVN clean package $MAVEN_ARGS

# Dependency
wget https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/1.0.2.3/bc-fips-1.0.2.3.jar
wget https://repo1.maven.org/maven2/org/bouncycastle/bctls-jdk15on/1.70/bctls-jdk15on-1.70.jar
wget https://repo1.maven.org/maven2/javax/servlet/javax.servlet-api/4.0.1/javax.servlet-api-4.0.1.jar

RUNTIME_CLASSPATH=

for JARFILE in $(find ./ -name "*.jar")
do
  if [[ "$JARFILE" == *"core/"* ]] || [[ "$JARFILE" == *"saml-core/"* ]] || \
  [[ "$JARFILE" == *"saml-core-api/"* ]] || [[ "$JARFILE" == *"common/"* ]] || \
  [[ "$JARFILE" == *"adapters/"* ]] || [[ "$JARFILE" == *"common/"* ]] || \
  [[ "$JARFILE" == *"crypto/"* ]] || [[ "$JARFILE" == *"bcprov"* ]] || \
  [[ "$JARFILE" == *"bcutil"* ]] || [[ "$JARFILE" == *"bcpkix"* ]] || \
  [[ "$JARFILE" == *"jboss-log"* ]] || [[ "$JARFILE" == *"jackson"* ]] || \
  [[ "$JARFILE" == *"wildfly"* ]] || [[ "$JARFILE" == *"javax.servlet"* ]] || \
  [[ "$JARFILE" == *"bc-fips"* ]] || [[ "$JARFILE" == *"bctls"* ]]
  then
    cp $JARFILE $OUT/
    RUNTIME_CLASSPATH=$RUNTIME_CLASSPATH\$this_dir/$(basename $JARFILE):
  fi
done

BUILD_CLASSPATH=$OUT/*:$JAZZER_API_PATH
RUNTIME_CLASSPATH=$RUNTIME_CLASSPATH:\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  $JAVA_HOME/bin/javac -cp $BUILD_CLASSPATH -d $SRC/ $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/


  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir JAVA_HOME=\$this_dir/jdk-17 \
PATH=$JAVA_HOME/bin:$PATH
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done

zip $OUT/SamlParserFuzzer_seed_corpus.zip $SRC/cncf-fuzzing/projects/keycloak/seeds/SamlParserFuzzer_seed1
zip $OUT/JwkParserFuzzer_seed_corpus.zip $SRC/cncf-fuzzing/projects/keycloak/seeds/JwkParserFuzzer_seed_1
zip $OUT/JoseParserFuzzer_seed_corpus.zip $SRC/cncf-fuzzing/projects/keycloak/seeds/json.seed
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/json.dict $OUT/JwkParserFuzzer.dict
cp $SRC/cncf-fuzzing/projects/keycloak/seeds/json.dict $OUT/JoseParserFuzzer.dict
