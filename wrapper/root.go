package wrapper

import (
	"errors"
	"fmt"
	"os"

	"github.com/EasyRecon/wappaGo/cmd"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
)

// StartReconAsync scans input and streams every result on results, which it
// closes when the scan is done. It blocks until then.
//
// Setup failures (fingerprint download, screenshot directory) are returned
// instead of being logged and ignored: a failed download used to leave the
// caller with a full scan reporting zero technologies for every host. results
// is left untouched — and unclosed — when a non-nil error is returned.
func StartReconAsync(input []string, wrapperOptions structure.WrapperOptions, results chan structure.Data) error {
	c, err := configureOptions(wrapperOptions)
	if err != nil {
		return err
	}
	c.Input = input

	c.Start(results)
	return nil
}

// StartReconSync scans input and returns every result once the scan is done.
func StartReconSync(input []string, wrapperOptions structure.WrapperOptions) ([]structure.Data, error) {
	c, err := configureOptions(wrapperOptions)
	if err != nil {
		return nil, err
	}
	c.Input = input

	var resultGlobal []structure.Data

	results := make(chan structure.Data)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for result := range results {
			resultGlobal = append(resultGlobal, result)
		}
	}()

	c.Start(results)
	// Waiting on done is what makes the slice safe to read: c.Start closing the
	// channel orders nothing with respect to the collector's last append, so
	// returning straight away both raced on resultGlobal and dropped whichever
	// results the collector had not appended yet.
	<-done

	return resultGlobal, nil
}

func configureOptions(wrapperOptions structure.WrapperOptions) (*cmd.Cmd, error) {
	// Every field gets its own pointer. Sharing one &falseBool across Report and
	// AmassInput made two unrelated options alias the same variable.
	noReport, noAmass, noProgress := false, false, true
	options := structure.Options{
		Screenshot:     &wrapperOptions.Screenshot,
		Ports:          &wrapperOptions.Ports,
		Threads:        &wrapperOptions.Threads,
		Report:         &noReport,
		Porttimeout:    &wrapperOptions.Porttimeout,
		ChromeTimeout:  &wrapperOptions.ChromeTimeout,
		ChromeThreads:  &wrapperOptions.ChromeThreads,
		Resolvers:      &wrapperOptions.Resolvers,
		AmassInput:     &noAmass,
		FollowRedirect: &wrapperOptions.FollowRedirect,
		Proxy:          &wrapperOptions.Proxy,
		UserAgent:      &wrapperOptions.UserAgent,
		Rps:            &wrapperOptions.Rps,
		Jitter:         &wrapperOptions.Jitter,
		NoProgress:     &noProgress, // library mode: no stderr progress bar
	}
	// A zero-valued WrapperOptions used to reach cmd with Threads=0 and
	// Porttimeout=0 — including in the README's own example.
	options.ApplyDefaults()

	if *options.Screenshot != "" {
		if _, err := os.Stat(*options.Screenshot); errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(*options.Screenshot, os.ModePerm); err != nil {
				return nil, fmt.Errorf("create screenshot dir %q: %w", *options.Screenshot, err)
			}
		}
	}

	// Downloads, parses, and deletes the on-disk copy before returning.
	resultGlobal, err := technologies.Load()
	if err != nil {
		return nil, fmt.Errorf("load technology fingerprints: %w", err)
	}

	c := &cmd.Cmd{}
	c.ResultGlobal = resultGlobal
	c.Options = options

	return c, nil
}
