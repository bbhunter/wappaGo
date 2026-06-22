package technologies

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	for name, _ := range entry {
		if name == "requires" {
			requires := entry["requires"]
			// Tentative d'assertion du type directement en string
			if reqString, ok := requires.(string); ok {
			    tech = AddTechno(reqString, tech, technoList)
			} else if reqMap, ok := requires.(map[string]interface{}); ok {
			    // Le contenu de requires est un map[string]interface{}, on itère sur les clés
			    for req := range reqMap {
			        tech = AddTechno(req, tech, technoList)
			    }
			} else if reqSlice, ok := requires.([]interface{}); ok {
			    // Le contenu de requires est un slice d'interface{}, on itère sur les éléments
			    for _, item := range reqSlice {
			        if itemStr, ok := item.(string); ok {
			            tech = AddTechno(itemStr, tech, technoList)
			        } else {
			            fmt.Println("Unsupported item type in 'requires' slice")
			        }
			    }
			} else {
			    // Si aucun des types attendus n'est rencontré, affiche une erreur
			    fmt.Println("Unexpected type for 'requires'")
			}
		}
		if name == "implies" {
			implies := entry["implies"]
			switch v := implies.(type) {
			case string:
			    // Si c'est une chaîne, on ajoute directement la technologie
			    tech = AddTechno(v, tech, technoList)
			case []interface{}:
			    // Si c'est un slice, on itère sur chaque élément
			    for _, item := range v {
			        if strItem, ok := item.(string); ok {
			            tech = AddTechno(strItem, tech, technoList)
			        } else {
			            fmt.Println("Unexpected item type in 'implies' slice")
			        }
			    }
			case map[string]interface{}:
			    // Si c'est un map, on itère sur chaque clé
			    for key := range v {
			        tech = AddTechno(key, tech, technoList)
			    }
			default:
			    fmt.Println("Unexpected type for 'implies'")
			}
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

		body, err := ioutil.ReadAll(resp.Body)
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
