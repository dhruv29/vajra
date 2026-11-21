package osv

import (
	"encoding/json"
	"regexp"
	"strings"
)

// The ecosystem names OSV uses for the lockfile formats read here.
const (
	ecosystemGo    = "Go"
	ecosystemNPM   = "npm"
	ecosystemPyPI  = "PyPI"
	ecosystemCargo = "crates.io"
	ecosystemGems  = "RubyGems"
)

const (
	nodeModulesDir = "node_modules/"
	cargoBlockHead = "[[package]]"
	gemSection     = "GEM"
	gemSpecsHead   = "  specs:"
	gemSpecIndent  = "    "
)

var (
	pythonNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	pythonVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.!+_-]*$`)
	cargoKeyPattern      = regexp.MustCompile(`^(name|version|source)\s*=\s*"([^"]*)"\s*$`)
	gemSpecPattern       = regexp.MustCompile(`^([A-Za-z0-9._-]+) \(([^)\s]+)\)$`)
)

func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// parseGoMod reads the require directives of a go.mod file, direct and
// indirect alike. Versions keep their leading "v": that is how Go writes them
// and OSV accepts them in that form.
func parseGoMod(text string) []Package {
	lines := splitLines(text)
	var out []Package
	inBlock := false
	for i, raw := range lines {
		line, _, _ := strings.Cut(raw, "//")
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
		case inBlock && fields[0] == ")":
			inBlock = false
		case inBlock:
			out = appendGoPin(out, fields, lines, i+1)
		case fields[0] == "require" && len(fields) == 2 && fields[1] == "(":
			inBlock = true
		case fields[0] == "require":
			out = appendGoPin(out, fields[1:], lines, i+1)
		}
	}
	return out
}

func appendGoPin(out []Package, fields, lines []string, line int) []Package {
	if len(fields) != 2 {
		return out
	}
	module, version := strings.Trim(fields[0], `"`), strings.Trim(fields[1], `"`)
	if module == "" || len(version) < 2 || version[0] != 'v' {
		return out
	}
	return append(out, Package{
		Ecosystem: ecosystemGo, Name: module, Version: version,
		Line: line, code: numbered(lines, line),
	})
}

// parsePackageLock reads the "packages" object of an npm lockfile (format 2
// and 3). Older lockfiles have no such object and give nothing.
func parsePackageLock(text string) []Package {
	var lock struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if json.Unmarshal([]byte(text), &lock) != nil {
		return nil
	}
	lines := splitLines(text)
	keyLines := jsonKeyLines(lines)
	var out []Package
	for key, raw := range lock.Packages {
		// Each entry is decoded on its own, so one of an unexpected shape
		// does not cost the rest of the file.
		var entry struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.Link || entry.Version == "" {
			continue
		}
		name := npmName(key, entry.Name)
		if name == "" {
			continue
		}
		line := keyLines[key]
		out = append(out, Package{
			Ecosystem: ecosystemNPM, Name: name, Version: entry.Version,
			Line: line, code: npmCode(lines, line),
		})
	}
	return out
}

// npmName returns the package installed at a "packages" key. The key is a
// path such as "node_modules/a/node_modules/b"; an entry installed under an
// alias carries its real name. Keys outside node_modules are the project
// itself or its workspaces, not third-party packages.
func npmName(key, declared string) string {
	at := strings.LastIndex(key, nodeModulesDir)
	if at < 0 {
		return ""
	}
	if declared != "" {
		return declared
	}
	return key[at+len(nodeModulesDir):]
}

// jsonKeyLines maps each node_modules object key to the first line it opens,
// by scanning the text: the JSON decoder does not report positions.
func jsonKeyLines(lines []string) map[string]int {
	found := make(map[string]int)
	for i, line := range lines {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), `"`+nodeModulesDir)
		if !ok {
			continue
		}
		name, _, ok := strings.Cut(rest, `":`)
		if !ok {
			continue
		}
		if key := nodeModulesDir + name; found[key] == 0 {
			found[key] = i + 1
		}
	}
	return found
}

// npmCode shows the key line and, when it follows directly as npm writes it,
// the version line.
func npmCode(lines []string, line int) string {
	if line > 0 && line < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[line]), `"version"`) {
		return numbered(lines, line, line+1)
	}
	return numbered(lines, line)
}

// parseRequirements reads the exact pins (name==version) of a pip
// requirements file. Ranges, options, URLs and includes pin nothing that can
// be looked up, and are skipped.
func parseRequirements(text string) []Package {
	lines := splitLines(text)
	var out []Package
	for i, raw := range lines {
		name, version, ok := pythonPin(raw)
		if !ok {
			continue
		}
		out = append(out, Package{
			Ecosystem: ecosystemPyPI, Name: name, Version: version,
			Line: i + 1, code: numbered(lines, i+1),
		})
	}
	return out
}

func pythonPin(raw string) (name, version string, ok bool) {
	line := strings.TrimSpace(raw)
	if line == "" || line[0] == '#' || line[0] == '-' {
		return "", "", false
	}
	line, _, _ = strings.Cut(line, " #")
	line, _, _ = strings.Cut(line, ";")   // environment marker
	line, _, _ = strings.Cut(line, " --") // per-requirement options such as --hash
	line = strings.TrimSuffix(line, `\`)  // continuation onto an option line
	name, version, ok = strings.Cut(line, "==")
	if !ok {
		return "", "", false
	}
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if extras := strings.IndexByte(name, '['); extras >= 0 && strings.HasSuffix(name, "]") {
		name = strings.TrimSpace(name[:extras])
	}
	if !pythonNamePattern.MatchString(name) || !pythonVersionPattern.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

// cargoBlock is one [[package]] table while it is being read.
type cargoBlock struct {
	name, version, source string
	nameLine, versionLine int
}

// parseCargoLock reads the [[package]] tables of a Cargo.lock file. A package
// with no source is the project's own crate or a path dependency, so it is
// left out.
func parseCargoLock(text string) []Package {
	lines := splitLines(text)
	var out []Package
	var block *cargoBlock
	flush := func() {
		if block != nil && block.name != "" && block.version != "" && block.source != "" {
			out = append(out, Package{
				Ecosystem: ecosystemCargo, Name: block.name, Version: block.version,
				Line: block.nameLine, code: numbered(lines, block.nameLine, block.versionLine),
			})
		}
		block = nil
	}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case line == cargoBlockHead:
			flush()
			block = &cargoBlock{}
		case strings.HasPrefix(line, "["):
			flush()
		case block != nil:
			block.set(line, i+1)
		}
	}
	flush()
	return out
}

func (b *cargoBlock) set(line string, number int) {
	m := cargoKeyPattern.FindStringSubmatch(line)
	if m == nil {
		return
	}
	switch m[1] {
	case "name":
		b.name, b.nameLine = m[2], number
	case "version":
		b.version, b.versionLine = m[2], number
	case "source":
		b.source = m[2]
	}
}

// parseGemfileLock reads the gems listed under "specs:" in the GEM section of
// a Gemfile.lock. The GIT and PATH sections name code that does not come from
// the gem registry, and the deeper-indented lines are version constraints,
// not pins.
func parseGemfileLock(text string) []Package {
	lines := splitLines(text)
	var out []Package
	section, inSpecs := "", false
	for i, line := range lines {
		switch {
		case line != "" && line[0] != ' ':
			section, inSpecs = strings.TrimSpace(line), false
		case line == gemSpecsHead:
			inSpecs = section == gemSection
		case inSpecs:
			name, version, ok := gemPin(line)
			if !ok {
				continue
			}
			out = append(out, Package{
				Ecosystem: ecosystemGems, Name: name, Version: version,
				Line: i + 1, code: numbered(lines, i+1),
			})
		}
	}
	return out
}

func gemPin(line string) (name, version string, ok bool) {
	spec, found := strings.CutPrefix(line, gemSpecIndent)
	if !found || strings.HasPrefix(spec, " ") {
		return "", "", false
	}
	m := gemSpecPattern.FindStringSubmatch(strings.TrimRight(spec, " "))
	if m == nil {
		return "", "", false
	}
	// A precompiled gem is written "1.15.4-x86_64-linux"; the advisory
	// database knows it by the version alone.
	version, _, _ = strings.Cut(m[2], "-")
	return m[1], version, version != ""
}
