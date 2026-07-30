package cmd

import (
	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

// dnsRecordTypes are the record types the fingerprint database actually matches
// against: 43 SOA patterns, 27 TXT, 18 NS, 5 CNAME and 4 MX. A is included
// because it is cheap and the answer is needed anyway.
var dnsRecordTypes = []uint16{
	dns.TypeA,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeTXT,
	dns.TypeMX,
	dns.TypeCNAME,
}

// dnsResolver answers the queries the dns fingerprint family needs.
//
// This used to piggyback on fastdialer's connection cache via GetDNSData, which
// happened to carry NS/SOA/TXT records as a side effect of dialing. Newer
// fastdialer only keeps the address records, so GetDNSData started returning
// A records and nothing else — silently killing all 80 dns fingerprints and the
// cname field with them. Asking a resolver directly is both explicit about which
// record types matter and no longer at the mercy of a dialer's caching strategy.
type dnsResolver struct {
	client *retryabledns.Client
}

func newDNSResolver(resolvers []string) (*dnsResolver, error) {
	client, err := retryabledns.New(resolvers, 2)
	if err != nil {
		return nil, err
	}
	return &dnsResolver{client: client}, nil
}

// resolve returns the records for host, or nil when the lookup fails. A nil
// result is expected (NXDOMAIN, a resolver hiccup) and every caller must handle
// it: the analyzer treats nil as "no dns signals" rather than dereferencing it.
func (r *dnsResolver) resolve(host string) *retryabledns.DNSData {
	if r == nil || r.client == nil || host == "" {
		return nil
	}
	data, err := r.client.QueryMultiple(host, dnsRecordTypes)
	if err != nil {
		return nil
	}
	return data
}
