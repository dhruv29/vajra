// Package llm is a small client for the Anthropic Messages API with tool use.
// It carries the conversation for the planner, the patch proposer and any
// other model call that needs more than one turn.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultModel is used when the configuration names none.
	DefaultModel = "claude-opus-5-5"

	defaultBaseURL   = "https://api.anthropic.com"
	apiVersion       = "2023-06-01"
	messagesPath     = "/v1/messages"
	maxResponseBytes = 4 << 20
	requestTimeout   = 180 * time.Second
	defaultMaxTokens = 2048
)

// Block types.
const (
	TypeText       = "text"
	TypeToolUse    = "tool_use"
	TypeToolResult = "tool_result"
)

// Block is one piece of a message.
type Block struct {
	Type string `json:"type"`
	// Text is set for text blocks.
	Text string `json:"text,omitempty"`
	// ID, Name and Input are set for tool_use blocks.
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// ToolUseID, Content and IsError are set for tool_result blocks.
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
}

// Message is one turn of the conversation.
type Message struct {
	Role    string  `json:"role"`
	Content []Block `json:"content"`
}

// Tool describes something the model may call.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolChoice forces or frees the model's use of tools. Type is "auto", "any"
// or "tool" (with Name).
type ToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// Request is one call to the model.
type Request struct {
	System     string
	Messages   []Message
	Tools      []Tool
	ToolChoice *ToolChoice
	MaxTokens  int
}

// Response is the model's reply.
type Response struct {
	Content      []Block
	StopReason   string
	InputTokens  int64
	OutputTokens int64
}

// Tokens is the total the call consumed.
func (r Response) Tokens() int64 { return r.InputTokens + r.OutputTokens }

// ToolUses returns the tool calls in the reply, in order.
func (r Response) ToolUses() []Block {
	var out []Block
	for _, b := range r.Content {
		if b.Type == TypeToolUse {
			out = append(out, b)
		}
	}
	return out
}

// Sender sends a request to a model. *Client is the real one.
type Sender interface {
	Send(ctx context.Context, req Request) (Response, error)
}

// Options configures a Client. Model, BaseURL and HTTP are optional.
type Options struct {
	APIKey  string
	Model   string
	BaseURL string
	HTTP    *http.Client
}

// Client calls the Messages API.
type Client struct {
	apiKey, model, baseURL string
	http                   *http.Client
}

// NewClient builds a client.
func NewClient(opts Options) (*Client, error) {
	if opts.APIKey == "" {
		return nil, errors.New("llm: an API key is required")
	}
	c := &Client{apiKey: opts.APIKey, model: opts.Model, baseURL: strings.TrimRight(opts.BaseURL, "/"), http: opts.HTTP}
	if c.model == "" {
		c.model = DefaultModel
	}
	if c.baseURL == "" {
		c.baseURL = defaultBaseURL
	}
	if c.http == nil {
		c.http = &http.Client{
			Timeout: requestTimeout,
			// The API key travels in a header that is not dropped on a
			// redirect to another host, so redirects are never followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return c, nil
}

type wireRequest struct {
	Model      string      `json:"model"`
	MaxTokens  int         `json:"max_tokens"`
	System     string      `json:"system,omitempty"`
	Messages   []Message   `json:"messages"`
	Tools      []Tool      `json:"tools,omitempty"`
	ToolChoice *ToolChoice `json:"tool_choice,omitempty"`
}

type wireResponse struct {
	Content    []Block `json:"content"`
	StopReason string  `json:"stop_reason"`
	Usage      struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type string `json:"type"`
	} `json:"error"`
}

// Send makes one call. Errors name the HTTP status and the API's error type,
// never the key or the reply body.
func (c *Client) Send(ctx context.Context, req Request) (Response, error) {
	if len(req.Messages) == 0 {
		return Response{}, errors.New("llm: a request needs at least one message")
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	body, err := json.Marshal(wireRequest{
		Model: c.model, MaxTokens: maxTokens, System: req.System,
		Messages: req.Messages, Tools: req.Tools, ToolChoice: req.ToolChoice,
	})
	if err != nil {
		return Response{}, fmt.Errorf("llm: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+messagesPath, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("llm: build request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("anthropic-version", apiVersion)
	httpReq.Header.Set("x-api-key", c.apiKey)

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("llm: call model: %w", err)
	}
	defer httpResp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return Response{}, fmt.Errorf("llm: read reply: %w", err)
	}
	var wire wireResponse
	decodeErr := json.Unmarshal(raw, &wire)
	if httpResp.StatusCode != http.StatusOK {
		if wire.Error != nil {
			return Response{}, fmt.Errorf("llm: model API returned %d (%s)", httpResp.StatusCode, wire.Error.Type)
		}
		return Response{}, fmt.Errorf("llm: model API returned %d", httpResp.StatusCode)
	}
	if decodeErr != nil {
		return Response{}, fmt.Errorf("llm: decode reply: %w", decodeErr)
	}
	return Response{
		Content: wire.Content, StopReason: wire.StopReason,
		InputTokens: wire.Usage.InputTokens, OutputTokens: wire.Usage.OutputTokens,
	}, nil
}

// UserText builds a user message holding one text block.
func UserText(text string) Message {
	return Message{Role: "user", Content: []Block{{Type: TypeText, Text: text}}}
}

// ToolResult builds the block that answers a tool call.
func ToolResult(toolUseID, content string, isError bool) Block {
	return Block{Type: TypeToolResult, ToolUseID: toolUseID, Content: content, IsError: isError}
}
