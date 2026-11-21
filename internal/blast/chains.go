package blast

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/topology"
)

const (
	// maxChainSteps bounds the search: longer paths are rarely credible and
	// the number of candidates grows with every step.
	maxChainSteps = 4
	// minChainSteps is what makes a chain: one finding alone is its radius.
	minChainSteps = 2
	// maxChains caps the result, keeping the highest scores.
	maxChains = 20

	extraStepPoints   = 8
	gainedClassPoints = 5

	maxTitleRunes = 60
	titleEllipsis = "..."
	// idSeparator joins finding IDs into a sort key; it cannot occur in one.
	idSeparator = "\x1f"
)

// Step is one finding in a chain.
type Step struct {
	FindingID  string     `json:"finding_id"`
	Title      string     `json:"title"`
	Capability Capability `json:"capability"`
	// OriginID is the asset the finding is on.
	OriginID string `json:"origin_id"`
	// Via is the asset, reached by the previous step, that makes this step
	// possible. Empty for the first step.
	Via string `json:"via,omitempty"`
	// Why says, in one sentence, why this step follows from the one before.
	Why string `json:"why"`
}

// Chain is a multi-step path: confirmed findings that combine because each
// becomes exploitable from somewhere the one before it reaches.
type Chain struct {
	Steps []Step `json:"steps"`
	// Reach is every asset ID reachable by the whole chain, sorted.
	Reach []string `json:"reach"`
	// DataClasses is the union over every step, sorted.
	DataClasses []string `json:"data_classes"`
	// Score is from 0 to 100.
	Score   int    `json:"score"`
	Summary string `json:"summary"`
}

// Chains finds chains among the findings. radii must be the radii computed
// for the same findings (match by FindingID). Only confirmed findings take
// part: a chain built on something unproven would overstate what the run
// showed. A finding with no radius, or whose radius has no origin in the
// graph, is ignored.
func Chains(g topology.Graph, findings []finding.Finding, radii []Radius) []Chain {
	s := newChainSearch(g, findings, radii)
	for start := range s.nodes {
		s.extend([]int{start}, s.nodes[start].depths)
	}
	chains := s.found
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Score != chains[j].Score {
			return chains[i].Score > chains[j].Score
		}
		return chainKey(chains[i]) < chainKey(chains[j])
	})
	if len(chains) > maxChains {
		chains = chains[:maxChains]
	}
	return chains
}

func chainKey(c Chain) string {
	ids := make([]string, 0, len(c.Steps))
	for _, step := range c.Steps {
		ids = append(ids, step.FindingID)
	}
	return strings.Join(ids, idSeparator)
}

// chainNode is one confirmed finding with what the search needs to know
// about its radius.
type chainNode struct {
	finding finding.Finding
	radius  Radius
	// depths maps every asset in the radius to its depth; the origin is 0.
	depths map[string]int
	// containers are the origin and the service and host that contain it,
	// most specific first.
	containers []string
}

// chainLink says why one finding can follow another.
type chainLink struct {
	via string
	why string
}

type chainSearch struct {
	assets map[string]topology.Asset
	// parents maps an asset to the services and hosts that contain it.
	parents map[string][]string
	// holders maps an identity to the assets that authenticate with it.
	holders map[string]map[string]bool
	nodes   []chainNode
	// links[a][b] is set when nodes[b] can follow nodes[a].
	links [][]*chainLink
	found []Chain
}

func newChainSearch(g topology.Graph, findings []finding.Finding, radii []Radius) *chainSearch {
	s := &chainSearch{
		assets:  map[string]topology.Asset{},
		parents: map[string][]string{},
		holders: map[string]map[string]bool{},
		found:   []Chain{},
	}
	for _, a := range g.Assets {
		s.assets[a.ID] = a
	}
	for _, e := range g.Edges {
		switch e.Relation {
		case topology.Serves, topology.Hosts:
			s.parents[e.To] = append(s.parents[e.To], e.From)
		case topology.AuthenticatesWith:
			if s.holders[e.To] == nil {
				s.holders[e.To] = map[string]bool{}
			}
			s.holders[e.To][e.From] = true
		}
	}
	s.nodes = s.eligible(findings, radii)
	s.links = make([][]*chainLink, len(s.nodes))
	for a := range s.nodes {
		s.links[a] = make([]*chainLink, len(s.nodes))
		for b := range s.nodes {
			s.links[a][b] = s.link(s.nodes[a], s.nodes[b])
		}
	}
	return s
}

// eligible pairs each confirmed finding with its radius. When an ID occurs
// twice the first occurrence is used, so no finding can appear twice.
func (s *chainSearch) eligible(findings []finding.Finding, radii []Radius) []chainNode {
	byFinding := map[string]Radius{}
	for _, r := range radii {
		if _, exists := byFinding[r.FindingID]; !exists {
			byFinding[r.FindingID] = r
		}
	}
	var nodes []chainNode
	seen := map[string]bool{}
	for _, f := range findings {
		r, ok := byFinding[f.ID]
		if !ok || seen[f.ID] || f.Status != finding.Confirmed || r.OriginID == "" {
			continue
		}
		seen[f.ID] = true
		depths := map[string]int{r.OriginID: 0}
		for _, h := range r.Reach {
			if depth, exists := depths[h.AssetID]; !exists || h.Depth < depth {
				depths[h.AssetID] = h.Depth
			}
		}
		nodes = append(nodes, chainNode{finding: f, radius: r, depths: depths, containers: s.containers(r.OriginID)})
	}
	return nodes
}

// containers returns id followed by the services and hosts that contain it,
// nearest first. The visited set keeps a declared cycle from looping.
func (s *chainSearch) containers(id string) []string {
	out, visited := []string{id}, map[string]bool{id: true}
	for level := []string{id}; len(level) > 0; {
		var next []string
		for _, child := range level {
			for _, parent := range s.parents[child] {
				if !visited[parent] {
					visited[parent] = true
					next = append(next, parent)
				}
			}
		}
		sort.Strings(next)
		out = append(out, next...)
		level = next
	}
	return out
}

// link decides whether b can follow a, and why. Two findings on the same
// asset do not chain: neither makes the other reachable.
func (s *chainSearch) link(a, b chainNode) *chainLink {
	if a.finding.ID == b.finding.ID || a.radius.OriginID == b.radius.OriginID {
		return nil
	}
	if l := s.reachLink(a, b); l != nil {
		return l
	}
	return s.credentialLink(a, b)
}

// reachLink holds when a reaches, beyond its own origin, the asset b is on
// or the service or host containing it.
func (s *chainSearch) reachLink(a, b chainNode) *chainLink {
	for _, id := range b.containers {
		if a.depths[id] < 1 {
			continue
		}
		why := fmt.Sprintf("The previous step reaches %s, which contains the asset this finding is on.", s.name(id))
		if id == b.radius.OriginID {
			why = fmt.Sprintf("The previous step reaches %s, the asset this finding is on.", s.name(id))
		}
		return &chainLink{via: id, why: why}
	}
	return nil
}

// leaksCredentials are the capabilities that hand an attacker a credential
// to use somewhere else, rather than only access from where they stand.
var leaksCredentials = map[Capability]bool{CredentialExposure: true, FileRead: true}

// credentialLink holds when a can leak a credential that the service or host
// behind b authenticates with.
func (s *chainSearch) credentialLink(a, b chainNode) *chainLink {
	if !leaksCredentials[a.radius.Capability] {
		return nil
	}
	for _, id := range slices.Sorted(maps.Keys(a.depths)) {
		if a.depths[id] < 1 || s.assets[id].Kind != topology.Identity {
			continue
		}
		for _, holder := range b.containers {
			if s.holders[id][holder] {
				return &chainLink{via: id, why: fmt.Sprintf(
					"The previous step can leak the credential %s, which belongs to %s, where this finding is.",
					s.name(id), s.name(holder))}
			}
		}
	}
	return nil
}

func (s *chainSearch) name(id string) string {
	if a, ok := s.assets[id]; ok && a.Name != "" {
		return a.Name
	}
	return id
}

// extend grows path depth-first. reach is everything the path reaches so
// far. A path is recorded only where it cannot grow, so no recorded chain is
// a prefix of another.
func (s *chainSearch) extend(path []int, reach map[string]int) {
	steps := s.nextSteps(path, reach)
	for _, next := range steps {
		wider := maps.Clone(reach)
		maps.Copy(wider, s.nodes[next].depths)
		s.extend(append(slices.Clone(path), next), wider)
	}
	if len(steps) == 0 && len(path) >= minChainSteps {
		s.found = append(s.found, s.chain(path, reach))
	}
}

// nextSteps lists the findings that can follow the end of path: linked to
// its last step, not already used, and adding to what the path reaches.
func (s *chainSearch) nextSteps(path []int, reach map[string]int) []int {
	if len(path) >= maxChainSteps {
		return nil
	}
	var steps []int
	last := path[len(path)-1]
	for next := range s.nodes {
		if s.links[last][next] != nil && !slices.Contains(path, next) && gains(s.nodes[next], reach) {
			steps = append(steps, next)
		}
	}
	return steps
}

// gains reports whether n reaches, beyond its own origin, anything the path
// does not reach already. The origin is not counted: the link into n already
// accounts for it, and counting it would let any finding on a reached
// service pass as a new step.
func gains(n chainNode, reach map[string]int) bool {
	for id, depth := range n.depths {
		if _, reached := reach[id]; depth >= 1 && !reached {
			return true
		}
	}
	return false
}

func (s *chainSearch) chain(path []int, reach map[string]int) Chain {
	c := Chain{Steps: make([]Step, 0, len(path)), Reach: slices.Sorted(maps.Keys(reach))}
	classes := map[string]bool{}
	best := 0
	for i, index := range path {
		n := s.nodes[index]
		step := Step{
			FindingID: n.finding.ID, Title: n.finding.Title, Capability: n.radius.Capability, OriginID: n.radius.OriginID,
			Why: fmt.Sprintf("The chain starts with %s on %s.", label(n.radius.Capability), s.name(n.radius.OriginID)),
		}
		if i > 0 {
			l := s.links[path[i-1]][index]
			step.Via, step.Why = l.via, l.why
		}
		c.Steps = append(c.Steps, step)
		for _, class := range n.radius.DataClasses {
			classes[class] = true
		}
		best = max(best, n.radius.Score)
	}
	// Appended to an empty slice so that no data classes is [] and not null.
	c.DataClasses = slices.AppendSeq([]string{}, maps.Keys(classes))
	sort.Strings(c.DataClasses)
	gained := 0
	for _, class := range c.DataClasses {
		if !slices.Contains(s.nodes[path[0]].radius.DataClasses, class) {
			gained++
		}
	}
	c.Score = min(maxScore, best+extraStepPoints*(len(path)-1)+gainedClassPoints*gained)
	c.Summary = summarizeChain(c)
	return c
}

func label(c Capability) string {
	return strings.ReplaceAll(string(c), "_", " ")
}

func summarizeChain(c Chain) string {
	titles := make([]string, 0, len(c.Steps))
	for _, step := range c.Steps {
		title := strings.TrimSpace(step.Title)
		if title == "" {
			title = step.FindingID
		}
		titles = append(titles, clip(title))
	}
	text := fmt.Sprintf("%d findings combine: %s; together they reach %d assets",
		len(c.Steps), strings.Join(titles, " -> "), len(c.Reach))
	if len(c.DataClasses) > 0 {
		text += " including data classed " + strings.Join(c.DataClasses, ", ")
	}
	return text + "."
}

// clip shortens a title to maxTitleRunes, marking the cut.
func clip(title string) string {
	runes := []rune(title)
	if len(runes) <= maxTitleRunes {
		return title
	}
	return string(runes[:maxTitleRunes-len(titleEllipsis)]) + titleEllipsis
}
