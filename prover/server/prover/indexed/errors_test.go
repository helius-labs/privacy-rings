package indexed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRPCBoundaryFailureCodes(t *testing.T) {
	for _, scenario := range []struct {
		name, body, contentType, code string
		transportErr                  error
	}{
		{name: "transport", code: "indexer_request_failed", transportErr: errors.New("https://private?api-key=secret")},
		{name: "timeout", code: "indexer_request_timeout", transportErr: context.DeadlineExceeded},
		{name: "cancel", code: "indexer_request_canceled", transportErr: context.Canceled},
		{name: "content type", contentType: "text/html", code: "indexer_invalid_content_type"},
		{name: "JSON", body: "private", code: "indexer_response_json_invalid"},
		{name: "version", body: `{"jsonrpc":"1.0","id":"getMerkleProofs","result":{}}`, code: "indexer_response_version_mismatch"},
		{name: "id", body: `{"jsonrpc":"2.0","id":"private","result":{}}`, code: "indexer_response_id_mismatch"},
		{name: "error", body: `{"jsonrpc":"2.0","id":"getMerkleProofs","error":{"message":"private"}}`, code: "indexer_rpc_error_invalid"},
		{name: "missing", body: `{"jsonrpc":"2.0","id":"getMerkleProofs"}`, code: "indexer_response_result_missing"},
		{name: "null", body: `{"jsonrpc":"2.0","id":"getMerkleProofs","result":null}`, code: "indexer_response_result_null"},
		{name: "size", body: strings.Repeat(" ", (2<<20)+1), code: "indexer_response_too_large"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			resolver, err := NewResolver(Config{URL: "https://indexer.test", Concurrency: 1})
			if err != nil {
				t.Fatal(err)
			}
			resolver.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				if scenario.transportErr != nil {
					return nil, scenario.transportErr
				}
				contentType := scenario.contentType
				if contentType == "" {
					contentType = "application/json"
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(scenario.body))}, nil
			})
			_, err = resolver.RPC(context.Background(), "getMerkleProofs", nil)
			var classified *Failure
			if !errors.As(err, &classified) || classified.Code != scenario.code {
				t.Fatalf("failure %v, expected %s", err, scenario.code)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatal("private text reached error")
			}
		})
	}
}

type unreadableResponse struct{}

func (unreadableResponse) Read([]byte) (int, error) {
	return 0, errors.New("private upstream response read failure")
}

func TestRPCReadFailureHasItsOwnCode(t *testing.T) {
	resolver, err := NewResolver(Config{URL: "https://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	resolver.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(unreadableResponse{})}, nil
	})
	_, err = resolver.RPC(context.Background(), "getMerkleProofs", nil)
	var classified *Failure
	if !errors.As(err, &classified) || classified.Code != "indexer_response_read_failed" || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsafe or unclassified read failure: %v", err)
	}
}
