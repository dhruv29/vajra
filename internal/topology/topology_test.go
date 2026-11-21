package topology

import (
	"slices"
	"testing"
)

func ids(g Graph) []string {
	out := make([]string, 0, len(g.Assets))
	for _, a := range g.Assets {
		out = append(out, a.ID)
	}
	return out
}

func hasEdge(g Graph, from, to string, rel Relation, origin Origin) bool {
	return slices.Contains(g.Edges, Edge{From: from, To: to, Relation: rel, Origin: origin})
}

func TestAddURLDerivesHostServiceAndEndpoint(t *testing.T) {
	b := NewBuilder()

	id := b.AddURL("https://App.Test/admin/users?id=7")
	g := b.Graph()

	if id != URLAssetID("https://App.Test/admin/users?id=7") || URLAssetID("nope") != "" {
		t.Fatal("URLAssetID disagrees with AddURL")
	}
	if id != "endpoint:https://app.test/admin/users" {
		t.Fatalf("id = %q; the query string must be dropped", id)
	}
	want := []string{"endpoint:https://app.test/admin/users", "host:app.test", "service:app.test:443"}
	if !slices.Equal(ids(g), want) {
		t.Fatalf("assets = %v", ids(g))
	}
	if !hasEdge(g, "host:app.test", "service:app.test:443", Hosts, Derived) ||
		!hasEdge(g, "service:app.test:443", id, Serves, Derived) {
		t.Fatalf("edges = %+v", g.Edges)
	}
}

func TestAddURLReturnsTheServiceForARootURLAndKeepsPortsApart(t *testing.T) {
	b := NewBuilder()

	root := b.AddURL("http://app.test")
	slash := b.AddURL("http://app.test/")
	other := b.AddURL("http://app.test:8080/")

	if root != "service:app.test:80" || slash != root || other != "service:app.test:8080" {
		t.Fatalf("ids = %q, %q, %q", root, slash, other)
	}
	if got := len(b.Graph().Assets); got != 3 {
		t.Fatalf("assets = %d; want one host and two services", got)
	}
}

func TestAddURLIgnoresNonHTTPAndIsIdempotent(t *testing.T) {
	b := NewBuilder()
	for _, bad := range []string{"app.test:22", "ftp://app.test/x", "://nope", "https:///path", ""} {
		if id := b.AddURL(bad); id != "" {
			t.Errorf("AddURL(%q) = %q; want empty", bad, id)
		}
	}
	b.AddURL("https://app.test/a")
	b.AddURL("https://app.test/a")

	g := b.Graph()
	if len(g.Assets) != 3 || len(g.Edges) != 2 {
		t.Fatalf("assets = %d, edges = %d; duplicates must collapse", len(g.Assets), len(g.Edges))
	}
}

func TestAddDeclarationLinksDeclaredAssetsToHosts(t *testing.T) {
	b := NewBuilder()
	b.AddURL("https://app.test/login")
	decl := Declaration{
		Assets: []DeclaredAsset{
			{ID: "orders-db", Kind: Datastore, Name: "Orders database", DataClasses: []string{" PII ", "payment", ""}},
			{ID: "deploy-key", Kind: Identity, Name: "Deploy key"},
		},
		Links: []DeclaredLink{
			{From: "app.test", To: "orders-db", Relation: Reads},
			{From: "app.test", To: "deploy-key", Relation: AuthenticatesWith},
			{From: "app.test", To: "billing.internal", Relation: Calls},
			{From: "orders-db", To: "orders-db", Relation: Calls}, // self-link is dropped
		},
	}

	if err := b.AddDeclaration(decl); err != nil {
		t.Fatal(err)
	}
	g := b.Graph()

	db, ok := g.Asset("orders-db")
	if !ok || db.Origin != Declared || !slices.Equal(db.DataClasses, []string{"payment", "pii"}) {
		t.Fatalf("orders-db = %+v", db)
	}
	if !hasEdge(g, "host:app.test", "orders-db", Reads, Declared) ||
		!hasEdge(g, "host:app.test", "deploy-key", AuthenticatesWith, Declared) ||
		!hasEdge(g, "host:app.test", "host:billing.internal", Calls, Declared) {
		t.Fatalf("edges = %+v", g.Edges)
	}
	if billing, ok := g.Asset("host:billing.internal"); !ok || billing.Origin != Declared {
		t.Fatalf("an undeclared link end must become a declared host: %+v", billing)
	}
	if app, _ := g.Asset("host:app.test"); app.Origin != Derived {
		t.Fatalf("a host the run touched must stay derived: %+v", app)
	}
	for _, e := range g.Edges {
		if e.From == e.To {
			t.Fatalf("self-link kept: %+v", e)
		}
	}
	if _, ok := g.Asset("missing"); ok {
		t.Fatal("Asset found an ID that does not exist")
	}
}

func TestDeclarationValidation(t *testing.T) {
	cases := map[string]Declaration{
		"asset without id":     {Assets: []DeclaredAsset{{Kind: Datastore, Name: "x"}}},
		"asset without name":   {Assets: []DeclaredAsset{{ID: "x", Kind: Datastore}}},
		"unsupported kind":     {Assets: []DeclaredAsset{{ID: "x", Kind: Endpoint, Name: "x"}}},
		"duplicate id":         {Assets: []DeclaredAsset{{ID: "x", Kind: Host, Name: "a"}, {ID: "x", Kind: Host, Name: "b"}}},
		"link without ends":    {Links: []DeclaredLink{{From: "a", Relation: Calls}}},
		"unsupported relation": {Links: []DeclaredLink{{From: "a", To: "b", Relation: Serves}}},
	}
	for name, decl := range cases {
		t.Run(name, func(t *testing.T) {
			if err := decl.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
			if err := NewBuilder().AddDeclaration(decl); err == nil {
				t.Fatal("AddDeclaration succeeded")
			}
		})
	}
	if err := (Declaration{}).Validate(); err != nil {
		t.Fatalf("an empty declaration must be valid: %v", err)
	}
}

func TestGraphOrderIsStable(t *testing.T) {
	build := func() Graph {
		b := NewBuilder()
		for _, u := range []string{"https://b.test/z", "https://a.test/y", "https://a.test/x", "http://a.test/x"} {
			b.AddURL(u)
		}
		return b.Graph()
	}
	first, second := build(), build()
	if !slices.Equal(ids(first), ids(second)) || !slices.Equal(first.Edges, second.Edges) {
		t.Fatal("two builds of the same input differ")
	}
	if !slices.IsSorted(ids(first)) {
		t.Fatalf("assets are not sorted: %v", ids(first))
	}
}
