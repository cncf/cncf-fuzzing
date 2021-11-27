# cncf-fuzzing
This repository is related to fuzzing of CNCF projects. It holds fuzzers as well as documentation on fuzzing

## CNCF projects and fuzzing
Fuzzing is a technique for automating stress testing of applications
and it can be used to find reliability and security issues. The technique
is traditionally used by security researchers to find security vulnerabilities, however,
fuzzing has become more integrated into the software development lifecycle
and is increasingly being used by developers. This includes many CNCF projects and
some example CNCF projects that use fuzzing include:
- [Envoy](https://github.com/envoyproxy/envoy/tree/main/test/fuzz)
- [Fluent-bit](https://github.com/fluent/fluent-bit/tree/master/tests/internal/fuzzers)
- [Linkerd2-proxy](https://github.com/linkerd/linkerd2-proxy/blob/main/docs/FUZZING.md)
- [Vitess](https://github.com/vitessio/vitess/blob/main/doc/VIT-02-report-fuzzing-audit.pdf)
- [Prometheus](https://github.com/prometheus/prometheus/blob/4c56a193c518ae6f56008b0a4c850a9c3f1477c6/promql/fuzz.go)
- [Kubernetes](https://github.com/kubernetes/kubernetes/tree/master/test/fuzz)
- [RunC](https://github.com/opencontainers/runc/tree/master/tests/fuzzing)
- [Containerd](https://github.com/containerd/containerd/tree/main/contrib/fuzz)

## Integrate fuzzing into your project
Integrating fuzzing into a project takes a lot effort and is often done 
over a long period of time. Fuzzing can be integrated into your project 
with various levels of maturity. There are three essential tasks when integrating fuzzing into your project:
- Develop fuzzers
- Execute the fuzzers
- Analyse crashes

The following describes three common steps in integrating fuzzing into your project.

### 1) Local fuzzing set up
The first step in integrating fuzzing into a project is to develop a set of fuzzers for your project. The fuzzer to use depends on which programming language your project is written in. The following list provides links to common fuzzers for various languages:
- C/C++: libFuzzer
- Rust: Cargo-fuzz
- Go: Go-fuzz and native go fuzzing
- Python: Atheris fuzzer
- Java: jazzer fuzzer

The specific purpose of a fuzzer can vary greatly. In essence, fuzzers are closely related to traditional tests and the difference is the fuzzer takes a random input which is used to enforce diverse code execution of the target code. Common goals of a fuzzer include:

- Execute large amounts of code to achieve high code coverage
- Execute a specific complex piece of code, e.g. parsing routines
- Execute code relative to the threat model of project

### 2) Integrate continuous fuzzing with OSS-Fuzz
Once you have developed a fuzzing infrastructure for your project, the next step is to run the fuzzers in a continuous manner. Modern fuzzers rely on genetic algorithms to build up an input corpus, which, in a simplified manner, means that the fuzzer by nature increases it’s quality in proportion to how long it has run. Continuously running a fuzzer is thus important to ensure high quality of the fuzzing and continuous fuzzing is also important in order to capture bugs that may occur as a project progresses.

OSS-Fuzz is a service for running fuzzers continuously for open source projects. OSS-Fuzz comes with a convenient management infrastructure with a dashboard as well as bug-tracking features, which makes managing running of the fuzzers easy. We recommend integrating with OSS-Fuzz, and several CNCF projects are integrated already.

### 3) Integrate fuzzing into CI
Fuzzing can be integrated in your CI, e.g. a GitHub action, such that the fuzzers run for a short amount of time on pull requests and/or push actions. This is in many ways similar to running tests as part of your CI to ensure regressions don’t occur. Once you have integrated with OSS-Fuzz, you can get CI integration by way of CIFuzz for free.

## What results to expect
Fuzzing works best with projects that have high code complexity, e.g. parsers, decoders, etc. but can be used in many other projects. You can fuzz projects in many languages and the type of bug you will find depends on which language your project is written in.

- Envoy has invested significantly in fuzzing and OSS-Fuzz has reported more than [700](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3Denvoy%20Type%3DBug&can=1) bugs as well as [81](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3Denvoy%20Type%3DBug-Security&can=1) security relevant bugs
- Fluent-bit has been fuzzed for slightly more than a year, and OSS-Fuzz has reported more than [100](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3Dfluent-bit%20Type%3DBug&can=1) reliability issues and more than [50](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3Dfluent-bit%20Type%3DBug-Security&can=1) security issues.

For an example where fuzzing was determined to have limited effects consider [Cloud custodian](https://github.com/cloud-custodian/cloud-custodian). Cloud custodian is a project written in Python and is very horisontal in its architecture in that it does not have deep code complexities. This is an example where fuzzing will have limited results as discussed in detail in a [PR](https://github.com/cloud-custodian/cloud-custodian/pull/6832) on the Cloud Custodian repository. However, Cloud Custodian still benefited from fuzzing finding a bug in the code of Cloud Custodian where fuzzing could be applied, but, in comparison to the other projects mentioned above Cloud Custodian is not integrated into OSS-Fuzz.

The following list indicates some common software properties that means your code is likely to benefit from fuzzing
- High code complexity
- Deep code paths
- Accepts untrusted input
- If a reliability or reliability issue occur then it can have significant consequences for systems
- Is used as a library by other applications
- Projects in memory unsafe languages should have a high prority for being fuzzed (but fuzzing is not exclusive to memory unsafe languages)
