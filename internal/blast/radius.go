package blast

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/topology"
)

// Confidence says how sure we are that an asset is reachable.
type Confidence string

const (
	// Proven means the run demonstrated it.
	Proven Confidence = "proven"
	// Inferred follows directly from what the vulnerability class allows.
	Inferred Confidence = "inferred"
	// Assumed is plausible but depends on facts the run did not check.
	Assumed Confidence = "assumed"
)

// Hop is one asset inside the blast radius.
type Hop struct {
	AssetID     string            `json:"asset_id"`
	Name        string            `json:"name"`
	Kind        topology.Kind     `json:"kind"`
	Depth       int               `json:"depth"`
	From        string            `json:"from,omitempty"`
	Via         topology.Relation `json:"via,omitempty"`
	Confidence  Confidence        `json:"confidence"`
	Why         string            `json:"why"`
	DataClasses []string          `json:"data_classes,omitempty"`
}

// Radius is the blast radius of one finding.
type Radius struct {
	FindingID       string     `json:"finding_id"`
	Capability      Capability `json:"capability"`
	CapabilityBasis string     `json:"capability_basis"`
	OriginID        string     `json:"origin_id"`
	Reach           []Hop      `json:"reach"`
	DataClasses     []string   `json:"data_classes"`
	Score           int        `json:"score"`
	Summary         string     `json:"summary"`
}

// step lets a capability cross one kind of edge.
type step struct {
	relation   topology.Relation
	confidence Confidence
	why        string
}

// rule describes how far one capability spreads.
type rule struct {
	// context, when set, puts the service and host behind the affected
	// endpoint inside the radius.
	context *step
	// siblings, when set, adds the other services on the same host.
	siblings *step
	// direct steps start from the affected asset, its service and its host.
	direct []step
	// onward steps start from assets reached through a "calls" edge.
	onward []step
}

var rules = map[Capability]rule{
	CodeExecution: {
		context:  &step{confidence: Inferred, why: "injected code runs with this service's privileges on its host"},
		siblings: &step{confidence: Inferred, why: "runs on the same host as the compromised service"},
		direct: []step{
			{topology.Reads, Inferred, "the compromised service can already read this data store"},
			{topology.AuthenticatesWith, Inferred, "the compromised service holds this credential"},
			{topology.Calls, Assumed, "reachable from the compromised service's network position"},
		},
		onward: []step{
			{topology.Reads, Assumed, "readable if the attacker moves on to the called service"},
			{topology.AuthenticatesWith, Assumed, "held by a service the attacker may move on to"},
		},
	},
	DataAccess: {
		context: &step{confidence: Inferred, why: "queries run with this service's database access"},
		direct: []step{
			{topology.Reads, Inferred, "the injectable service reads this data store"},
		},
	},
	FileRead: {
		context: &step{confidence: Inferred, why: "files readable by this service are exposed"},
		direct: []step{
			{topology.AuthenticatesWith, Assumed, "credentials are often stored in files the service can read"},
		},
	},
	CredentialExposure: {
		context: &step{confidence: Inferred, why: "the exposed credential belongs to this service"},
		direct: []step{
			{topology.AuthenticatesWith, Inferred, "this credential may be the one exposed"},
			{topology.Reads, Assumed, "an exposed credential may grant the same access the service has"},
		},
	},
	AuthBypass: {
		context: &step{confidence: Inferred, why: "functions behind this service's login become reachable"},
		direct: []step{
			{topology.Reads, Inferred, "data the service exposes to authenticated users"},
		},
	},
	RequestForgery: {
		context:  &step{confidence: Inferred, why: "requests are sent from this service's network position"},
		siblings: &step{confidence: Assumed, why: "local services may be reachable from the forging service"},
		direct: []step{
			{topology.Calls, Inferred, "the service can already reach this, so a forged request can too"},
		},
	},
}

const (
	maxScore        = 100
	maxReachPoints  = 30
	maxDataPoints   = 25
	sensitivePoints = 10
	otherDataPoints = 4
)

var severityPoints = map[finding.Severity]float64{
	finding.SeverityCritical: 45, finding.SeverityHigh: 35, finding.SeverityMedium: 22,
	finding.SeverityLow: 10, finding.SeverityInfo: 4, finding.SeverityUnknown: 12,
}

// statusFactor discounts findings that were not confirmed. Refuted and
// out-of-scope findings have no blast radius.
var statusFactor = map[finding.Status]float64{
	finding.Confirmed: 1, finding.Unconfirmed: 0.6, finding.Candidate: 0.5,
}

var confidencePoints = map[Confidence]float64{Proven: 6, Inferred: 5, Assumed: 3}

var sensitiveClasses = map[string]bool{
	"pii": true, "payment": true, "credentials": true, "secrets": true,
	"health": true, "financial": true, "auth": true,
}

// Compute estimates the blast radius of f within g.
func Compute(g topology.Graph, f finding.Finding) Radius {
	capability, basis := Classify(f)
	r := Radius{FindingID: f.ID, Capability: capability, CapabilityBasis: basis, DataClasses: []string{}}
	origin, ok := g.Asset(topology.URLAssetID(f.Target))
	if !ok {
		r.Reach = []Hop{}
		r.Summary = "The affected asset is not in the asset graph, so no reach was computed."
		return r
	}
	r.OriginID = origin.ID

	w := newWalk(g)
	originConfidence, originWhy := Assumed, "reported by the scanner but not confirmed"
	if f.Status == finding.Confirmed {
		originConfidence, originWhy = Proven, "the finding was reproduced here"
	}
	w.add(Hop{AssetID: origin.ID, Depth: 0, Confidence: originConfidence, Why: originWhy})
	if statusFactor[f.Status] > 0 {
		w.apply(rules[capability], origin.ID)
	}

	r.Reach = w.hops()
	r.DataClasses = dataClasses(r.Reach)
	r.Score = score(f, r)
	r.Summary = summarize(f, r, origin)
	return r
}

// walk collects hops, keeping the first (shallowest) route to each asset.
type walk struct {
	graph topology.Graph
	seen  map[string]Hop
}

func newWalk(g topology.Graph) *walk {
	return &walk{graph: g, seen: map[string]Hop{}}
}

func (w *walk) add(h Hop) bool {
	if _, exists := w.seen[h.AssetID]; exists {
		return false
	}
	asset, ok := w.graph.Asset(h.AssetID)
	if !ok {
		return false
	}
	h.Name, h.Kind, h.DataClasses = asset.Name, asset.Kind, asset.DataClasses
	w.seen[h.AssetID] = h
	return true
}

// parent returns the asset with an edge of the given relation into id.
func (w *walk) parent(id string, relation topology.Relation) string {
	for _, e := range w.graph.Edges {
		if e.To == id && e.Relation == relation {
			return e.From
		}
	}
	return ""
}

func (w *walk) apply(r rule, originID string) {
	sources := []string{originID}
	serviceID, hostID := w.context(originID)
	if r.context != nil {
		for _, id := range []string{serviceID, hostID} {
			if id != "" && w.add(Hop{AssetID: id, Depth: 1, From: originID, Confidence: r.context.confidence, Why: r.context.why}) {
				sources = append(sources, id)
			}
		}
	}
	if r.siblings != nil && hostID != "" {
		w.follow([]string{hostID}, []step{{topology.Hosts, r.siblings.confidence, r.siblings.why}}, 2)
	}
	called := w.follow(sources, r.direct, 2)
	w.follow(called, r.onward, 3)
}

// context finds the service and host behind an asset.
func (w *walk) context(id string) (serviceID, hostID string) {
	asset, _ := w.graph.Asset(id)
	switch asset.Kind {
	case topology.Endpoint:
		serviceID = w.parent(id, topology.Serves)
		hostID = w.parent(serviceID, topology.Hosts)
	case topology.Service:
		hostID = w.parent(id, topology.Hosts)
	}
	return serviceID, hostID
}

// follow crosses the allowed edges out of sources and returns the assets
// newly reached through a "calls" edge.
func (w *walk) follow(sources []string, steps []step, depth int) []string {
	var called []string
	for _, source := range sources {
		for _, e := range w.graph.Edges {
			if e.From != source {
				continue
			}
			for _, s := range steps {
				if e.Relation != s.relation {
					continue
				}
				added := w.add(Hop{AssetID: e.To, Depth: depth, From: source, Via: e.Relation, Confidence: s.confidence, Why: s.why})
				if added && e.Relation == topology.Calls {
					called = append(called, e.To)
				}
			}
		}
	}
	return called
}

func (w *walk) hops() []Hop {
	out := make([]Hop, 0, len(w.seen))
	for _, h := range w.seen {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].AssetID < out[j].AssetID
	})
	return out
}

func dataClasses(hops []Hop) []string {
	set := map[string]bool{}
	for _, h := range hops {
		for _, c := range h.DataClasses {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// score ranks findings from 0 to 100 by severity, how far the damage spreads
// and how sensitive the reachable data is, discounted when unconfirmed.
func score(f finding.Finding, r Radius) int {
	factor := statusFactor[f.Status]
	if factor == 0 {
		return 0
	}
	reach := 0.0
	for _, h := range r.Reach {
		if h.Depth > 0 {
			reach += confidencePoints[h.Confidence]
		}
	}
	data := 0.0
	for _, c := range r.DataClasses {
		if sensitiveClasses[c] {
			data += sensitivePoints
		} else {
			data += otherDataPoints
		}
	}
	total := severityPoints[f.Severity] + math.Min(reach, maxReachPoints) + math.Min(data, maxDataPoints)
	return int(math.Min(math.Round(total*factor), maxScore))
}

func summarize(f finding.Finding, r Radius, origin topology.Asset) string {
	if statusFactor[f.Status] == 0 {
		return "No blast radius: this finding was " + strings.ReplaceAll(string(f.Status), "_", " ") + "."
	}
	beyond := len(r.Reach) - 1
	label := strings.ReplaceAll(string(r.Capability), "_", " ")
	if beyond == 0 {
		return fmt.Sprintf("Limited to %s (%s).", origin.Name, label)
	}
	text := fmt.Sprintf("From %s, %s reaches %d further asset(s)", origin.Name, label, beyond)
	if len(r.DataClasses) > 0 {
		text += ", including data classed " + strings.Join(r.DataClasses, ", ")
	}
	return text + "."
}
