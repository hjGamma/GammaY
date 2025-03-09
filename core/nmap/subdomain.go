package nmap

import (
	"bytes"
	"context"
	"gammay/core/task"
	"gammay/utils/logger"
	"io"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func SubdomainInit(Tp *task.TaskPool, MaxEnumerationTime int) *runner.Options {
	subfinderOpts := &runner.Options{
		Threads:            Tp.Params.Thread,       // Thread controls the number of threads to use for active enumerations
		Timeout:            int(Tp.Params.Timeout), // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: MaxEnumerationTime,     // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		// ResultCallback: func(s *resolve.HostEntry) {
		// callback function executed after each unique subdomain is found
		// },
		// ProviderConfig: "your_provider_config.yaml",
		// and other config related options

	}
	return subfinderOpts
}

func Subdomaindetect(subfinderOpts *runner.Options) func() {
	return func() {
		subfinder, err := runner.NewRunner(subfinderOpts)
		if err != nil {
			logger.Fatal(logger.Global.Color().Red("failed to create subfinder runner: %v", err.Error()))
		}
		output := &bytes.Buffer{}
		var sourceMap map[string]map[string]struct{}
		if sourceMap, err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), Tp.Params.Domain[0], []io.Writer{output}); err != nil {
			logger.Fatalf("failed to enumerate single domain: %v", err)
		}
		logger.Info(output.String())
		for subdomain, sources := range sourceMap {
			sourcesList := make([]string, 0, len(sources))
			for source := range sources {
				sourcesList = append(sourcesList, source)
			}
			logger.Printf("%s %s (%d)\n", subdomain, sourcesList, len(sources))
		}
	}
}
