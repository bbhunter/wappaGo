package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/EasyRecon/wappaGo/cmd"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
)

func main() {
	options := structure.Options{}
	options.Screenshot = flag.String("screenshot", "", "path to screenshot if empty no screenshot")
	options.Ports = flag.String("ports", "80,443", "port want to scan separated by coma")
	options.Threads = flag.Int("threads", 5, "Number of threads to start recon in same time")
	options.Report = flag.Bool("report", false, "Generate HTML report")
	options.Porttimeout = flag.Int("port-timeout", 2000, "Timeout during port scanning in ms")
	//options.ChromeTimeout = flag.Int("chrome-timeout", 0000, "Timeout during navigation (chrome) in sec")
	options.ChromeThreads = flag.Int("chrome-threads", 5, "Number of chromes threads in each main threads total = option.threads*option.chrome-threads (Default 5)")
	options.Resolvers = flag.String("resolvers", "", "Use specifique resolver separated by comma")
	options.AmassInput = flag.Bool("amass-input", false, "Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo")
	options.FollowRedirect = flag.Bool("follow-redirect", false, "Follow redirect to detect technologie")
	options.Proxy = flag.String("proxy", "", "Use http proxy")
	options.UserAgent = flag.String("user-agent", structure.DefaultUserAgent, "User-Agent sent by both the HTTP probe and Chrome (blank keeps the built-in browser UA)")
	options.Rps = flag.Float64("rps", 0, "Max HTTP requests per second per host to stay under rate-based WAF rules (0 = unlimited)")
	options.Jitter = flag.Int("jitter", 0, "Max random delay in ms added before each request (0 = none)")
	options.NoProgress = flag.Bool("no-progress", false, "Disable the stderr progress bar")
	options.Headless = flag.Bool("headless", false, "Run Chrome without a display. Off by default: headless fakes an 800x600 screen and brands its own User-Agent. Needs a display otherwise (use xvfb-run on a server)")
	flag.Parse()
	configure(options)
}

func configure(options structure.Options) {
	if *options.Screenshot != "" {
		if _, err := os.Stat(*options.Screenshot); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(*options.Screenshot, os.ModePerm)
			if err != nil {
				log.Println(err)
			}
		}
	}
	// The fingerprint database is downloaded, parsed and the on-disk copy
	// deleted before this returns. Without it every host would report zero
	// technologies, so a failure here is fatal rather than a logged warning.
	resultGlobal, errDownload := technologies.Load()
	if errDownload != nil {
		log.Fatalf("could not load the technology fingerprints: %v", errDownload)
	}

	var input []string
	var scanner = bufio.NewScanner(bufio.NewReader(os.Stdin))
	for scanner.Scan() {
		input = append(input, scanner.Text())
	}

	c := cmd.Cmd{}
	c.ResultGlobal = resultGlobal
	c.Options = options
	c.Input = input

	// Buffer the results channel so producer goroutines (up to
	// Threads*ChromeThreads of them) don't serialise on the single stdout
	// consumer.
	resultsBuffer := *options.Threads * *options.ChromeThreads
	if resultsBuffer < 1 {
		resultsBuffer = 1
	}
	results := make(chan structure.Data, resultsBuffer)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for result := range results {
			b, err := json.Marshal(result)

			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(b))
		}
	}()

	c.Start(results)
	// Start closes the channel, but closing only wakes the consumer — it does
	// not wait for it. Returning here would exit the process with up to
	// resultsBuffer already-scanned hosts still sitting unprinted in the
	// buffer, silently losing them on a perfectly successful run.
	<-done
}
