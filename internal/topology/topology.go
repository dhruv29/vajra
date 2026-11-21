// Package topology is the asset graph: what exists and how it is connected.
//
// Part of the graph is derived from the URLs a run touched (host, service,
// endpoint). The rest is declared by the operator, who knows which service
// reads which data store. Every edge records which of the two it came from,
// so nothing inferred is presented as fact.
package topology

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Kind is the type of an asset.
type Kind string

const (
	Host      Kind = "host"
	Service   Kind = "service"
	Endpoint  Kind = "endpoint"
	Datastore Kind = "datastore"
	Identity  Kind = "identity"
	External  Kind = "external"
)

// Relation is how one asset is connected to another.
type Relation string

const (
	// Hosts links a host to a service running on it.
	Hosts Relation = "hosts"
	// Serves links a service to one of its endpoints.
	Serves Relation = "serves"
	// Calls links a service to something it makes requests to.
	Calls Relation = "calls"
	// Reads links a service to a data store it can read.
	Reads Relation = "reads"
	// AuthenticatesWith links a service to an identity or secret it holds.
	AuthenticatesWith Relation = "authenticates_with"
)

// Origin says where a fact in the graph came from.
type Origin string

const (
	// Derived facts follow from a URL the run touched.
	Derived Origin = "derived"
	// Declared facts were stated by the operator in the configuration.
	Declared Origin = "declared"
)

// Asset is one node of the graph.
type Asset struct {
	ID          string   `json:"id"`
	Kind        Kind     `json:"kind"`
	Name        string   `json:"name"`
	DataClasses []string `json:"data_classes,omitempty"`
	Origin      Origin   `json:"origin"`
}

// Edge is one directed connection.
type Edge struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Relation Relation `json:"relation"`
	Origin   Origin   `json:"origin"`
}

// Graph is an asset graph. Build one with a Builder.
type Graph struct {
	Assets []Asset `json:"assets"`
	Edges  []Edge  `json:"edges"`
}

// DeclaredAsset is an asset the operator described in the configuration.
type DeclaredAsset struct {
	ID          string   `json:"id"`
	Kind        Kind     `json:"kind"`
	Name        string   `json:"name"`
	DataClasses []string `json:"data_classes"`
}

// DeclaredLink is a connection the operator described. From and To are a
// declared asset ID or a host name that appears in the run.
type DeclaredLink struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Relation Relation `json:"relation"`
}

// Declaration is the operator's description of the environment.
type Declaration struct {
	Assets []DeclaredAsset `json:"assets"`
	Links  []DeclaredLink  `json:"links"`
}

var declarableKinds = map[Kind]bool{Host: true, Service: true, Datastore: true, Identity: true, External: true}

var declarableRelations = map[Relation]bool{Calls: true, Reads: true, AuthenticatesWith: true, Hosts: true}

// Validate reports the first problem with a declaration.
func (d Declaration) Validate() error {
	seen := map[string]bool{}
	for _, a := range d.Assets {
		if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Name) == "" {
			return errors.New("topology: every declared asset needs an id and a name")
		}
		if !declarableKinds[a.Kind] {
			return fmt.Errorf("topology: asset %q has unsupported kind %q", a.ID, a.Kind)
		}
		if seen[a.ID] {
			return fmt.Errorf("topology: asset id %q is declared twice", a.ID)
		}
		seen[a.ID] = true
	}
	for _, l := range d.Links {
		if strings.TrimSpace(l.From) == "" || strings.TrimSpace(l.To) == "" {
			return errors.New("topology: every link needs a from and a to")
		}
		if !declarableRelations[l.Relation] {
			return fmt.Errorf("topology: link %q -> %q has unsupported relation %q", l.From, l.To, l.Relation)
		}
	}
	return nil
}

// HostID is the asset ID of a host name.
func HostID(host string) string { return "host:" + strings.ToLower(host) }

// ServiceID is the asset ID of a host and port.
func ServiceID(host, port string) string { return "service:" + strings.ToLower(host) + ":" + port }

// EndpointID is the asset ID of a URL.
func EndpointID(rawURL string) string { return "endpoint:" + rawURL }

// Builder assembles a Graph without duplicates.
type Builder struct {
	assets map[string]Asset
	edges  map[Edge]bool
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{assets: map[string]Asset{}, edges: map[Edge]bool{}}
}

func (b *Builder) addAsset(a Asset) {
	if _, exists := b.assets[a.ID]; !exists {
		b.assets[a.ID] = a
	}
}

func (b *Builder) addEdge(e Edge) {
	if e.From != e.To {
		b.edges[e] = true
	}
}

// urlParts is what a URL contributes to the graph.
type urlParts struct {
	host, port, scheme string
	// endpoint is the URL without its query string, or "" for a root URL.
	endpoint string
}

func splitURL(rawURL string) (urlParts, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return urlParts{}, false
	}
	p := urlParts{host: strings.ToLower(u.Hostname()), port: u.Port(), scheme: u.Scheme}
	if p.port == "" {
		p.port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if u.Path != "" && u.Path != "/" {
		// The query string is dropped: it is test input, not a distinct asset.
		p.endpoint = u.Scheme + "://" + strings.ToLower(u.Host) + u.Path
	}
	return p, true
}

// URLAssetID returns the ID of the most specific asset a URL names: the
// endpoint, or the service when the URL has no path. It returns "" for
// anything that is not an http(s) URL.
func URLAssetID(rawURL string) string {
	p, ok := splitURL(rawURL)
	if !ok {
		return ""
	}
	if p.endpoint == "" {
		return ServiceID(p.host, p.port)
	}
	return EndpointID(p.endpoint)
}

// AddURL derives the host, service and endpoint a URL names and returns
// URLAssetID(rawURL).
func (b *Builder) AddURL(rawURL string) string {
	p, ok := splitURL(rawURL)
	if !ok {
		return ""
	}
	hostID, serviceID := HostID(p.host), ServiceID(p.host, p.port)
	b.addAsset(Asset{ID: hostID, Kind: Host, Name: p.host, Origin: Derived})
	b.addAsset(Asset{ID: serviceID, Kind: Service, Name: p.scheme + "://" + p.host + ":" + p.port, Origin: Derived})
	b.addEdge(Edge{From: hostID, To: serviceID, Relation: Hosts, Origin: Derived})
	if p.endpoint == "" {
		return serviceID
	}
	endpointID := EndpointID(p.endpoint)
	b.addAsset(Asset{ID: endpointID, Kind: Endpoint, Name: p.endpoint, Origin: Derived})
	b.addEdge(Edge{From: serviceID, To: endpointID, Relation: Serves, Origin: Derived})
	return endpointID
}

// AddDeclaration adds the operator's assets and links. A link end that is not
// a declared asset ID is taken to be a host name.
func (b *Builder) AddDeclaration(d Declaration) error {
	if err := d.Validate(); err != nil {
		return err
	}
	declared := map[string]bool{}
	for _, a := range d.Assets {
		declared[a.ID] = true
		b.addAsset(Asset{
			ID: a.ID, Kind: a.Kind, Name: a.Name, Origin: Declared,
			DataClasses: normalizeClasses(a.DataClasses),
		})
	}
	for _, l := range d.Links {
		b.addEdge(Edge{
			From: b.resolve(l.From, declared), To: b.resolve(l.To, declared),
			Relation: l.Relation, Origin: Declared,
		})
	}
	return nil
}

func (b *Builder) resolve(ref string, declared map[string]bool) string {
	if declared[ref] {
		return ref
	}
	id := HostID(ref)
	b.addAsset(Asset{ID: id, Kind: Host, Name: strings.ToLower(ref), Origin: Declared})
	return id
}

func normalizeClasses(classes []string) []string {
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// Graph returns the assembled graph in a stable order.
func (b *Builder) Graph() Graph {
	g := Graph{Assets: make([]Asset, 0, len(b.assets)), Edges: make([]Edge, 0, len(b.edges))}
	for _, a := range b.assets {
		g.Assets = append(g.Assets, a)
	}
	for e := range b.edges {
		g.Edges = append(g.Edges, e)
	}
	sort.Slice(g.Assets, func(i, j int) bool { return g.Assets[i].ID < g.Assets[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool {
		a, c := g.Edges[i], g.Edges[j]
		if a.From != c.From {
			return a.From < c.From
		}
		if a.To != c.To {
			return a.To < c.To
		}
		return a.Relation < c.Relation
	})
	return g
}

// Asset looks up an asset by ID.
func (g Graph) Asset(id string) (Asset, bool) {
	for _, a := range g.Assets {
		if a.ID == id {
			return a, true
		}
	}
	return Asset{}, false
}
