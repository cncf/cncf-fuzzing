package github

import (
	"bytes"
	"io"
	"net/http"
	"os"

	"github.com/argoproj/argo-events/eventsources/common/webhook"

	zap "go.uber.org/zap"

	"github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"

	"github.com/AdaLogics/go-fuzz-headers/sanitizers/logsanitizer"
)

var (
	logger     = NewFuzzLogger()
	fRoute     = webhook.GetFakeRoute()
	router     *Router
	logFileAbs = "/tmp/argo-logfile"
)

func init() {

	fRoute.Logger = logger
	router = &Router{
		route:             fRoute,
		githubEventSource: &v1alpha1.GithubEventSource{},
	}
}

func NewFuzzLogger() *zap.SugaredLogger {
	var config zap.Config
	config = zap.NewProductionConfig()
	// Config customization goes here if any
	config.OutputPaths = []string{logFileAbs}
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	return logger.Named("argo-events").Sugar()
}

func setupLogSanitizer() (*logsanitizer.Sanitizer, *os.File, error) {
	logFile, err := os.Create(logFileAbs)
	if err != nil {
		return nil, nil, err
	}

	logSanitizer := logsanitizer.NewSanitizer()
	logSanitizer.SetLogFile(logFileAbs)
	return logSanitizer, logFile, nil
}

func FuzzGithubEventsource(data []byte) int {
	logSAN, logFp, err := setupLogSanitizer()
	if err != nil {
		panic(err)
	}

	defer runLogSanitizer(logSAN, logFp)

	router.route.Active = true
	writer := &webhook.FakeHttpWriter{}
	r := &http.Request{
		Body: io.NopCloser(bytes.NewReader(data)),
	}
	r.Header = make(map[string][]string)
	r.Header.Set("Content-Type", "application/json")
	router.HandleRoute(writer, r)
	return 1
}

func runLogSanitizer(logSAN *logsanitizer.Sanitizer, logFp *os.File) {
	logSAN.CheckLogfile()
	logFp.Close()
	os.Remove(logFileAbs)
}
