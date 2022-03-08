FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/kubernetes-sigs/cluster-api
RUN cd $SRC && go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
RUN git clone --depth 1 --branch cluster-api https://github.com/AdamKorcz/cncf-fuzzing $SRC/cncf-fuzzing
RUN mv $SRC/cncf-fuzzing/projects/cluster-api/non-oss-fuzz/build.sh $SRC/
WORKDIR $SRC/cluster-api
ENV FUZZING_LANGUAGE go
ENV FUZZER fuzz_cluster_controller
ENV FUZZ_TIME 600
RUN compile
RUN mkdir -p /usr/local/kubebuilder/bin
CMD ["sh", "-c", "export KUBEBUILDER_BINARIES=$(setup-envtest use -p path) && mv ${KUBEBUILDER_BINARIES}/* /usr/local/kubebuilder/bin/ && /out/${FUZZER} -max_total_time=${FUZZ_TIME}"]

