package technologies

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/EasyRecon/wappaGo/lib"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/imdario/mergo"
)
func CheckRequired(technoName string, technoList map[string]interface{}, tech []structure.Technologie) []structure.Technologie {
	entry, ok := technoList[technoName].(map[string]interface{})
	if !ok {
		return tech
	}
	// Only "implies" adds technologies (X implies Y means Y is also present).
	// "requires" is a precondition, NOT an assertion: it is enforced after all
	// detection by FilterRequired, so it is intentionally ignored here.
	implies, ok := entry["implies"]
	if !ok {
		return tech
	}
	switch v := implies.(type) {
	case string:
		tech = AddTechno(v, tech, technoList)
	case []interface{}:
		for _, item := range v {
			if strItem, ok := item.(string); ok {
				tech = AddTechno(strItem, tech, technoList)
			}
		}
	case map[string]interface{}:
		for key := range v {
			tech = AddTechno(key, tech, technoList)
		}
	}
	return tech
}
func AddTechno(name string, tech []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	technoTemp := structure.Technologie{Name: name}
	// Guard every step: the implied/required techno may be missing from the DB
	// or carry a nil/non-string cpe (the original code panicked on both).
	if entry, ok := technoList[name].(map[string]interface{}); ok {
		if cpe, ok := entry["cpe"].(string); ok {
			technoTemp.Cpe = cpe
		}
	}
	tech = append(tech, technoTemp)
	return tech
}

func DownloadTechnologies() (string, error) {
	files := []string{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
	// Create the working dir under the system temp location, not the current
	// working directory, so the downloaded fingerprint shards never land in
	// (and get accidentally committed to) the repository.
	folder, err := os.MkdirTemp("", "wappago-")
	if err != nil {
		return "", err
	}
	for _, f := range files {
		url := fmt.Sprintf("%v/technologies/%v.json", structure.WappazlyerRoot, f)
		resp, err := http.Get(url)
		if err != nil {
			return "", err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %v.json: read error: %v\n", f, err)
			continue
		}
		// A 404/HTML error page must not be written as fingerprint data and
		// then merged silently — skip any shard that didn't return 200 OK.
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "skip %v.json: unexpected status %d\n", f, resp.StatusCode)
			continue
		}
		file, err := os.OpenFile(
			folder+"/"+f+".json",
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %v.json: %v\n", f, err)
			continue
		}
		file.Write(body)
		file.Close()

	}
	return folder, nil
}

func LoadTechnologiesFiles(folder string) map[string]interface{} {
	resultGlobal := make(map[string]interface{})
	for _, s := range lib.Find(folder, ".json") {
		result, err := loadTechnologyFile(s)
		if err != nil {
			// A corrupt or unreadable shard is skipped (and reported) instead
			// of being merged as empty/garbage and silently degrading detection.
			fmt.Fprintf(os.Stderr, "skip %v: %v\n", s, err)
			continue
		}
		if err := mergo.Merge(&resultGlobal, result); err != nil {
			fmt.Fprintf(os.Stderr, "merge %v: %v\n", s, err)
		}
	}
	return resultGlobal
}

// loadTechnologyFile reads and parses a single fingerprint shard. The file is
// fully read and closed before returning, so descriptors are released per
// iteration rather than piling up until LoadTechnologiesFiles returns.
func loadTechnologyFile(path string) (map[string]interface{}, error) {
	byteValue, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(byteValue, &result); err != nil {
		return nil, err
	}
	return result, nil
}
func DedupTechno(technologies []structure.Technologie) []structure.Technologie {
	var output []structure.Technologie
	add := true
	for _, tech := range technologies {
		add = true
		for i, checkTech := range output {
			if checkTech == tech {
				add = false
			} else {
				if checkTech.Name == tech.Name {
					if tech.Version != "" && checkTech.Version == "" {
						output[i].Version = tech.Version
					}
					add = false
				}
			}
		}
		if add {
			output = append(output, tech)
		}
	}
	return output
}

// FilterRequired enforces Wappalyzer "requires" preconditions: a detected
// technology is kept only if every technology it requires is also present in
// the result set. Unlike "implies" (which asserts a dependency), "requires"
// gates the detection itself, so this drops false positives such as a plugin
// reported without the platform it depends on.
//
// It iterates to a fixpoint so a chain (A requires B requires C) collapses
// correctly when the root is missing. "requiresCategory" is not enforced
// because categories are not loaded.
func FilterRequired(techs []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	for {
		detected := make(map[string]bool, len(techs))
		for _, t := range techs {
			detected[t.Name] = true
		}
		kept := techs[:0:0]
		for _, t := range techs {
			if requiresSatisfied(t.Name, technoList, detected) {
				kept = append(kept, t)
			}
		}
		if len(kept) == len(techs) {
			return kept
		}
		techs = kept
	}
}

func requiresSatisfied(name string, technoList map[string]interface{}, detected map[string]bool) bool {
	entry, ok := technoList[name].(map[string]interface{})
	if !ok {
		return true
	}
	requires, ok := entry["requires"]
	if !ok {
		return true
	}
	for _, req := range requiredNames(requires) {
		if !detected[req] {
			return false
		}
	}
	return true
}

// requiredNames normalises a "requires" value (string, []interface{} or
// map[string]interface{}) into the list of required technology names.
func requiredNames(requires interface{}) []string {
	switch v := requires.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]interface{}:
		var out []string
		for k := range v {
			out = append(out, k)
		}
		return out
	}
	return nil
}
