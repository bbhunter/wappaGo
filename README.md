# WappaGo

<p align="center">  
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>  
    <a href="https://github.com/EasyRecon/Hunt3r/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>  
    <a href="https://github.com/EasyRecon/Hunt3r"><img src="https://img.shields.io/badge/release-v0.0.8-informational"></a>
    <a href="https://github.com/easyrecon/wappago/issues" target="_blank"><img src="https://img.shields.io/github/issues/easyrecon/wappago?color=blue" /></a>
</p>

<p align="center">  
    <a href="https://codeclimate.com/github/EasyRecon/wappaGo"><img src="https://codeclimate.com/github/EasyRecon/wappaGo.png"></a>
</p>

<p align="center">
  <a href="#about">About WappaGo</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a>
</p>

# About
WappaGo has been developed to assemble different features from tools like [HTTPX](https://github.com/projectdiscovery/httpx), [Naabu](https://github.com/projectdiscovery/naabu), [GoWitness](https://github.com/sensepost/gowitness) and [Wappalyzer](https://github.com/wappalyzer/wappalyzer).
To allow an efficient detection of technologies, it is necessary to open a browser and in order to avoid opening a browser for each target, WappaGo opens only one browser and uses the system of pages which allows to consume less resources and to carry out an analysis much more quickly.

# Installation

Download the latest [release](https://github.com/EasyRecon/wappaGo/releases)  or compile by yourself :

```bash
git clone https://github.com/EasyRecon/wappaGo
cd wappaGo && go build 
```
or
```
go install github.com/EasyRecon/wappaGo@latest
```

**Note :** _wappaGo requires Chrome to be present on the system_

# Usage



```
Usage of wappaGo:
  -amass-input
        Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo
  -chrome-threads int
        Number of chromes threads in each main threads total = option.threads*option.chrome-threads (Default 5) (default 5)
  -follow-redirect
        Follow redirect to detect technologie
  -jitter int
        Max random delay in ms added before each request (0 = none)
  -no-progress
        Disable the stderr progress bar
  -port-timeout int
        Timeout during port scanning in ms (default 2000)
  -ports string
        port want to scan separated by coma (default "80,443")
  -proxy string
        Use http proxy
  -report
        Generate HTML report (in addition to the JSON on stdout)
  -resolvers string
        Use specifique resolver separated by comma
  -rps float
        Max HTTP requests per second per host to stay under rate-based WAF rules (0 = unlimited)
  -screenshot string
        path to screenshot if empty no screenshot
  -threads int
        Number of threads to start recon in same time (default 5)
  -user-agent string
        User-Agent sent by both the HTTP probe and Chrome (blank keeps the built-in browser UA)

```

Results are written to stdout as one JSON object per line, so `-report` can be
combined with a redirect:

```bash
cat domain.txt | ./wappaGo -report > results.json   # JSON on stdout + wappaGo_report.html
```

The technology fingerprints are downloaded at startup from
[Serizao/tech](https://github.com/Serizao/tech), parsed into memory, and the
on-disk copy is deleted before the scan begins.

You can either use wappaGo from a file containing a list of domains
```bash
cat domain.txt | ./wappaGo
```

or from an Amass output  (preferred)

```bash
amass enum -d example.com -ipv4 -json out.json
cat out.json | ./wappaGo -amass-input
```

# Library

You can use wappaGo as a library in your own project.

## Options
      
```go
type WrapperOptions struct {
	Screenshot     string
	Ports          string
	Threads        int
	Porttimeout    int
	Resolvers      string
	FollowRedirect bool
	ChromeTimeout  int
	ChromeThreads  int
	Proxy          string
	UserAgent      string
	Rps            float64
	Jitter         int
}
```

Any field left at its zero value falls back to the same default as the
corresponding CLI flag (`Ports: "80,443"`, `Threads: 5`, `ChromeThreads: 5`,
`Porttimeout: 2000`), so you only have to set what you want to change.

## Example

Both entry points return an `error`, which is non-nil when the setup itself
failed — most often because the technology fingerprints could not be downloaded.
Ignoring it means scanning every host with an empty database and reporting zero
technologies everywhere.

```go
package main

import (
	"fmt"
	"log"

	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/wrapper"
)

func main() {
	input := []string{"google.com", "twitter.com"}

	options := structure.WrapperOptions{
		Ports:      "80,443",
		Screenshot: "screenshots",
	}

	// Sync mode: blocks, then returns everything.
	results, err := wrapper.StartReconSync(input, options)
	if err != nil {
		log.Fatal(err)
	}
	for _, result := range results {
		fmt.Println(result)
	}
}
```

```go
	// Async mode: results are streamed on the channel, which wrapper closes
	// when the scan is done. StartReconAsync blocks until then, so run the
	// consumer in its own goroutine and wait for it to drain.
	results := make(chan structure.Data)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for result := range results {
			fmt.Println(result)
		}
	}()

	if err := wrapper.StartReconAsync(input, options, results); err != nil {
		log.Fatal(err)
	}
	<-done
```

For each url, you will receive a structure.Data which contains all the information about the target.

## Todo



  - Add robot technologie dectection
  - Add xhr technologie dectection


## Thank's

This tool uses several [ProjectDiscovery](https://github.com/projectdiscovery) libraries
