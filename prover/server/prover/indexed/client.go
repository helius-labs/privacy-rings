package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/helius-labs/zolana/prover/server/prover/timing"
)

type Config struct {
	MaxBatchLeaves uint64
	URL            string
	APIKey         string
	Concurrency    int
}

type Resolver struct {
	maxBatchLeaves uint64
	batchReplay    batchReplay
	batchLock      chan struct{}
	batch          batchCache
	client         *http.Client
	url            string
	apiKey         string
	permits        chan struct{}
}

const DefaultMaxBatchLeaves = 1_000_000

func NewResolver(config Config) (*Resolver, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil {
		return nil, failure("indexer_url_unparseable", "unparseable indexer URL")
	}
	if endpoint.Host == "" || endpoint.User != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return nil, failure("indexer_invalid_url", "invalid indexer URL")
	}
	if config.Concurrency < 1 {
		return nil, failure("indexer_invalid_concurrency", "invalid indexer concurrency")
	}
	if config.MaxBatchLeaves == 0 {
		config.MaxBatchLeaves = DefaultMaxBatchLeaves
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = config.Concurrency * 2
	transport.MaxConnsPerHost = config.Concurrency * 2
	return &Resolver{
		maxBatchLeaves: config.MaxBatchLeaves,
		url:            endpoint.String(), apiKey: config.APIKey,
		permits:   make(chan struct{}, config.Concurrency),
		batchLock: make(chan struct{}, 1),
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// RPCError keeps only structured diagnostics; the upstream message may contain
// request values and must not reach logs or the decrypted client response.
type RPCError struct {
	Code        int    `json:"code"`
	Method      string `json:"-"`
	Diagnostics struct {
		Code string `json:"code"`
	} `json:"data"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("indexer error %d", e.Code)
}

// HTTPError distinguishes an upstream HTTP rejection from a JSON-RPC error.
type HTTPError struct {
	Status int
	Method string
}

func (failure *HTTPError) Error() string {
	return fmt.Sprintf("indexer response status %d", failure.Status)
}

// Rejection code and detail reach the client.
type Rejection struct {
	Outcome string
	Code    string
	Message string
	Detail  map[string]string
}

func (e *Rejection) Error() string {
	return e.Message
}

type proofQuery struct {
	Method string
	Tree   string
	Leaves []Hash
}

type proofParams struct {
	Tree   string `json:"treeAccount"`
	Leaves []Hash `json:"leaves"`
}

func (r *Resolver) call(ctx context.Context, query proofQuery) (json.RawMessage, error) {
	return r.RPC(ctx, query.Method, proofParams{Tree: query.Tree, Leaves: query.Leaves})
}

func (r *Resolver) RPC(ctx context.Context, method string, params any) (json.RawMessage, error) {
	finish := timing.FromContext(ctx).Start(method)
	defer finish()
	body, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{JSONRPC: "2.0", ID: method, Method: method, Params: params})
	if err != nil {
		return nil, failure("indexer_request_encode_failed", "cannot encode indexer request")
	}
	endpoint, err := url.Parse(r.url)
	if err != nil {
		return nil, failure("indexer_invalid_url", "invalid indexer URL")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + method
	if r.apiKey != "" {
		parameters := endpoint.Query()
		parameters.Set("api-key", r.apiKey)
		endpoint.RawQuery = parameters.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, failure("indexer_request_create_failed", "cannot create indexer request")
	}
	request.Header.Set("Content-Type", "application/json")
	result, err := r.client.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, failure("indexer_request_timeout", "indexer request timed out")
		}
		if errors.Is(err, context.Canceled) {
			return nil, failure("indexer_request_canceled", "indexer request canceled")
		}
		return nil, failure("indexer_request_failed", "indexer request failed")
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		return nil, &HTTPError{Status: result.StatusCode, Method: method}
	}
	mediaType, _, err := mime.ParseMediaType(result.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, failure("indexer_invalid_content_type", "invalid indexer content type")
	}
	const maxResponse = 2 << 20
	data, err := io.ReadAll(io.LimitReader(result.Body, maxResponse+1))
	if err != nil {
		return nil, failure("indexer_response_read_failed", "indexer response read failed")
	}
	if len(data) > maxResponse {
		return nil, failure("indexer_response_too_large", "indexer response exceeds size limit")
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return nil, failure("indexer_response_json_invalid", "invalid indexer response JSON")
	}
	if envelope.JSONRPC != "2.0" {
		return nil, failure("indexer_response_version_mismatch", "invalid indexer JSON-RPC version")
	}
	if envelope.ID != method {
		return nil, failure("indexer_response_id_mismatch", "indexer response ID mismatch")
	}
	if len(envelope.Error) != 0 {
		var rpcFailure RPCError
		if json.Unmarshal(envelope.Error, &rpcFailure) == nil && rpcFailure.Code != 0 {
			rpcFailure.Method = method
			rpcFailure.Diagnostics.Code = knownRPCReason(rpcFailure.Diagnostics.Code, rpcFailure.Code)
			return nil, &rpcFailure
		}
		return nil, failure("indexer_rpc_error_invalid", "invalid indexer JSON-RPC error")
	}
	if len(envelope.Result) == 0 {
		return nil, failure("indexer_response_result_missing", "indexer response result missing")
	}
	if bytes.Equal(envelope.Result, []byte("null")) {
		return nil, failure("indexer_response_result_null", "indexer response result is null")
	}
	return envelope.Result, nil
}

func knownRPCReason(code string, rpcCode int) string {
	expected := -32600
	switch code {
	case "output_leaf_not_found", "validation_error", "invalid_pubkey", "record_not_found", "stale_slot", "stale_root":
	case "minimum_context_slot":
		expected = -32016
	case "database_error", "unexpected_error":
		expected = -32603
	default:
		return ""
	}
	if rpcCode != expected {
		return ""
	}
	return code
}
