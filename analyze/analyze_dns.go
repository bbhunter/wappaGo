package analyze

import (
	"github.com/EasyRecon/wappaGo/technologies"
)

func (a *Analyze) analyze_dns_main(technoName string, key string) {
	// DnsData is nil whenever resolution failed — fastdialer returns (nil, err)
	// on NXDOMAIN or a resolver hiccup, and launchChrome assigned it anyway.
	// Dereferencing it panicked, and the per-port recover() then dropped the
	// whole target from the output without a word.
	if a.DnsData == nil {
		return
	}
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	records, ok := entry[key].(map[string]interface{})
	if !ok {
		return
	}
	for key, value := range records {
		var resultDNS []string
		switch key {
		case "TXT":
			resultDNS = a.DnsData.TXT
		case "SOA":
			resultDNS = a.DnsData.SOA
		case "NS":
			resultDNS = a.DnsData.NS
		case "CNAME":
			resultDNS = a.DnsData.CNAME
		case "MX":
			resultDNS = a.DnsData.MX
		}
		for _, regex := range namesOfValue(value) {
			if a.analyze_dns_regex(regex, resultDNS) {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		}
	}
}

func (a *Analyze) analyze_dns_regex(regex string, resultsDNS []string) bool {
	re, ok := compileCI(regex)
	if !ok {
		return false
	}
	for _, resultDNS := range resultsDNS {
		if re.MatchString(resultDNS) {
			return true
		}
	}
	return false
}
