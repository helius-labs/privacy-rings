package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/indexed"
)

func TestIndexedRPCReasonsReachSyncAndQueuedClients(t *testing.T) {
	for _, scenario := range []struct {
		reason  string
		rpcCode int
		status  int
		code    string
	}{
		{"output_leaf_not_found", -32600, http.StatusUnprocessableEntity, "indexer_rpc_output_leaf_not_found"},
		{"validation_error", -32600, http.StatusUnprocessableEntity, "indexer_rpc_validation_error"},
		{"invalid_pubkey", -32600, http.StatusUnprocessableEntity, "indexer_rpc_invalid_pubkey"},
		{"stale_root", -32600, http.StatusServiceUnavailable, "indexer_rpc_stale_root"},
		{"stale_slot", -32600, http.StatusServiceUnavailable, "indexer_rpc_stale_slot"},
		{"minimum_context_slot", -32016, http.StatusServiceUnavailable, "indexer_rpc_minimum_context_slot"},
		{"record_not_found", -32600, http.StatusBadGateway, "indexer_rpc_record_not_found"},
		{"database_error", -32603, http.StatusBadGateway, "indexer_rpc_database_error"},
		{"unexpected_error", -32603, http.StatusBadGateway, "indexer_rpc_unexpected_error"},
		{"", -32600, http.StatusBadGateway, "indexer_rpc_-32600"},
		{"output_leaf_not_found", -32603, http.StatusBadGateway, "indexer_rpc_-32603"},
		{"private-upstream-text", -32099, http.StatusBadGateway, "indexer_rpc_-32099"},
	} {
		t.Run(scenario.code, func(t *testing.T) {
			photon := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				var query struct {
					Method string `json:"method"`
				}
				if err := json.NewDecoder(request.Body).Decode(&query); err != nil {
					t.Error(err)
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				writer.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(writer).Encode(map[string]any{
					"jsonrpc": "2.0", "id": query.Method,
					"error": map[string]any{"code": scenario.rpcCode, "message": "private upstream message", "data": map[string]string{"code": scenario.reason}},
				}); err != nil {
					t.Error(err)
				}
			}))
			defer photon.Close()
			resolver, err := indexed.NewResolver(indexed.Config{URL: photon.URL, Concurrency: 1})
			if err != nil {
				t.Fatal(err)
			}
			readiness := NewReadiness()
			readiness.MarkReady()
			handler := proveHandler{readiness: readiness, indexer: resolver, indexed: true, transferExecution: &Execution{admission: newSyncAdmission(1)}}
			requestBytes := indexedTransferRequest(t)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prove/transfer_confidential_2_2/indexed", bytes.NewReader(requestBytes)))
			var actual struct {
				Code, Message string
				Detail        map[string]string
			}
			if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil {
				t.Fatal(err)
			}
			if response.Code != scenario.status || actual.Code != scenario.code || actual.Detail["rpcCode"] != strconv.Itoa(scenario.rpcCode) || actual.Detail["method"] == "" {
				t.Fatalf("response %d: %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "private") {
				t.Fatal("upstream text escaped redaction")
			}
			if retryable := response.Header().Get("Retry-After") != ""; retryable != (scenario.status == http.StatusServiceUnavailable) {
				t.Fatal("wrong retry classification")
			}

			// Exercise the actual worker/Redis path, not just its error converter.
			_, queue := newTestQueue(t)
			runOneJob(t, queue, "zk_transfer_queue", WorkerConfig{Indexer: resolver}, &ProofJob{ID: "rpc-failure", Indexed: true, Payload: requestBytes})
			assertClientSees(t, queue, "rpc-failure", errIndexedProof.Error(), scenario.code)
		})
	}
}
