package analyze

import (
	"github.com/EasyRecon/wappaGo/technologies"
)

// analyze_cert_main matches the TLS issuer CN. The fingerprint value used to be
// asserted to string unconditionally, panicking on any technology that ships
// certIssuer as an array.
func (a *Analyze) analyze_cert_main(technoName string, key string) {
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok || a.CertIssuer == "" {
		return
	}
	for _, issuer := range namesOfValue(entry[key]) {
		if a.CertIssuer != issuer {
			continue
		}
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		return
	}
}

// namesOfValue normalises a fingerprint value that may be a bare string or an
// array of strings into a slice.
func namesOfValue(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
