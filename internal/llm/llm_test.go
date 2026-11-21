package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func server(t *testing.T, status int, reply string) (*httptest.Server, *wireRequest, *http.Header) {
	t.Helper()
	var got wireRequest
	var header http.Header
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("request is not JSON: %v", err)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(s.Close)
	return s, &got, &header
}

func client(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(Options{APIKey: "test-key", BaseURL: baseURL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSendCarriesAToolConversation(t *testing.T) {
	reply := `{"content":[{"type":"text","text":"checking"},{"type":"tool_use","id":"tu_1","name":"http_request","input":{"url":"https://app.test/"}}],
	  "stop_reason":"tool_use","usage":{"input_tokens":120,"output_tokens":30}}`
	s, got, header := server(t, http.StatusOK, reply)
	req := Request{
		System: "be careful",
		Messages: []Message{
			UserText("start"),
			{Role: "assistant", Content: []Block{{Type: TypeToolUse, ID: "tu_0", Name: "http_request", Input: json.RawMessage(`{"url":"x"}`)}}},
			{Role: "user", Content: []Block{ToolResult("tu_0", "HTTP 200", false)}},
		},
		Tools:      []Tool{{Name: "http_request", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		ToolChoice: &ToolChoice{Type: "auto"},
	}

	resp, err := client(t, s.URL).Send(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	uses := resp.ToolUses()
	if len(uses) != 1 || uses[0].Name != "http_request" || uses[0].ID != "tu_1" || string(uses[0].Input) != `{"url":"https://app.test/"}` {
		t.Fatalf("tool uses = %+v", uses)
	}
	if resp.StopReason != "tool_use" || resp.Tokens() != 150 || resp.Content[0].Text != "checking" {
		t.Fatalf("response = %+v", resp)
	}
	if header.Get("x-api-key") != "test-key" || header.Get("anthropic-version") != apiVersion {
		t.Fatalf("headers = %v", *header)
	}
	if got.Model != DefaultModel || got.MaxTokens != defaultMaxTokens || got.System != "be careful" || len(got.Messages) != 3 ||
		got.Messages[2].Content[0].ToolUseID != "tu_0" || got.ToolChoice.Type != "auto" || len(got.Tools) != 1 {
		t.Fatalf("wire request = %+v", got)
	}
}

func TestSendFailuresNeverLeakTheKeyOrTheBody(t *testing.T) {
	cases := map[string]struct {
		status int
		reply  string
		want   string
	}{
		"api error":      {http.StatusTooManyRequests, `{"error":{"type":"rate_limit_error","message":"key test-key is limited"}}`, "429 (rate_limit_error)"},
		"plain error":    {http.StatusBadGateway, "<html>gateway body</html>", "502"},
		"ok but garbage": {http.StatusOK, "garbage", "decode reply"},
	}
	for name, tc := range cases {
		s, _, _ := server(t, tc.status, tc.reply)
		_, err := client(t, s.URL).Send(context.Background(), Request{Messages: []Message{UserText("x")}})
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "test-key") || strings.Contains(err.Error(), "gateway body") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSendRejectsEmptyRequestsCancellationAndDeadServers(t *testing.T) {
	s, _, _ := server(t, http.StatusOK, `{"content":[]}`)
	c := client(t, s.URL)
	if _, err := c.Send(context.Background(), Request{}); err == nil {
		t.Error("an empty conversation was sent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Send(ctx, Request{Messages: []Message{UserText("x")}}); err == nil {
		t.Error("a cancelled call succeeded")
	}
	s.Close()
	if _, err := c.Send(context.Background(), Request{Messages: []Message{UserText("x")}}); err == nil {
		t.Error("a dead server was not reported")
	}
}

func TestNewClientDefaultsAndValidation(t *testing.T) {
	if _, err := NewClient(Options{}); err == nil {
		t.Error("a missing key was accepted")
	}
	c, _ := NewClient(Options{APIKey: "k", Model: "claude-sonnet-5-5"})
	if c.model != "claude-sonnet-5-5" || c.baseURL != defaultBaseURL || c.http == nil {
		t.Fatalf("client = %+v", c)
	}
	s, got, _ := server(t, http.StatusOK, `{"content":[{"type":"text","text":"ok"}],"usage":{}}`)
	custom, _ := NewClient(Options{APIKey: "k", BaseURL: s.URL})
	if _, err := custom.Send(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 77}); err != nil || got.MaxTokens != 77 {
		t.Fatalf("max tokens = %d, err = %v", got.MaxTokens, err)
	}
}
