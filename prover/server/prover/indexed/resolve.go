package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/timing"
	prooftranscript "github.com/helius-labs/zolana/prover/server/prover/transcript"

	"golang.org/x/sync/errgroup"
)

type Resolved struct {
	Payload    json.RawMessage
	Resolution *common.ProofResolution
}

type treeProofs struct {
	state      response[stateProof]
	exclusion  response[nullifierProof]
	inputs     []int
	realInputs []int
}

type Resolution func(context.Context, *Resolver) (*Resolved, error)

// Decode validates an extension circuit's indexed request.
type Decode func(data []byte) (Resolution, error)

type Limits struct {
	Trees        int
	PublicInputs int
}

var extensions = map[common.CircuitType]Decode{}

// Register runs in an extension package init.
func Register(circuit common.CircuitType, decode Decode) {
	if _, exists := extensions[circuit]; exists {
		panic(fmt.Sprintf("indexed circuit %s is already registered", circuit))
	}
	extensions[circuit] = decode
}

func Validate(data []byte) error {
	if batchCircuit(data) {
		_, err := decodeBatch(data)
		return err
	}
	_, err := decode(data)
	return err
}

func decode(data []byte) (Resolution, error) {
	if extension, ok := extensions[requestCircuit(data)]; ok {
		return extension(data)
	}
	request, prepared, err := decodeRequest(data)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r *Resolver) (*Resolved, error) {
		return r.ResolvePrepared(ctx, request, prepared)
	}, nil
}

func decodeRequest(data []byte) (Request, *Prepared, error) {
	var request Request
	if err := DecodeEnvelope(data, &request); err != nil {
		return request, nil, err
	}
	expected := 17
	switch request.CircuitType {
	case common.TransferRingAuthorityCircuitType:
		expected = 14
	case common.TransferAnonymousRingEddsaCircuitType, common.TransferConfidentialEddsaCircuitType:
		// The confidential layout plus the message hash and one owner field:
		// the hidden default owner, or the identity of the in-circuit owner.
		expected = 19
	case common.MergeCircuitType:
		// The prefix without the tree hash, the two-element owner tail, the
		// ciphertext salt and the three ciphertext elements.
		expected = 12
	case common.MergeRingCircuitType:
		// The prefix without the tree hash and the two-element ring tail; the
		// ring merge proof binds no ciphertext.
		expected = 8
	}
	if err := request.Check(Limits{Trees: 2, PublicInputs: expected}); err != nil {
		return request, nil, err
	}
	prepared, err := decodePrepared(request)
	return request, prepared, err
}

func (request Request) Check(limits Limits) error {
	if len(request.Trees) == 0 || len(request.Trees) > limits.Trees {
		return failure("indexer_invalid_input_tree_count", "invalid input tree count")
	}
	for index, tree := range request.Trees {
		if _, err := decodeHash(tree.Address); err != nil {
			return failure("indexer_invalid_tree_address", "invalid tree address")
		}
		for _, previous := range request.Trees[:index] {
			if tree.ID == previous.ID || tree.Address == previous.Address {
				return failure("indexer_duplicate_input_tree", "duplicate input tree")
			}
		}
	}
	if len(request.PublicInputs) != limits.PublicInputs {
		return failure("indexer_invalid_public_input_count", "invalid public input count")
	}
	for _, encoded := range request.PublicInputs {
		field, err := common.FeFromHex(encoded)
		if err != nil || encoded == "" {
			return failure("indexer_invalid_public_input", "invalid public input")
		}
		if _, err := HashField(field); err != nil {
			return err
		}
	}
	if requestCircuit(request.Prepared) != request.CircuitType {
		return failure("indexer_prepared_circuit_mismatch", "prepared circuit mismatch")
	}
	return nil
}

// Admit holds one of the resolver's concurrent preparation permits.
func (r *Resolver) Admit(ctx context.Context) (release func(), err error) {
	select {
	case r.permits <- struct{}{}:
		return func() { <-r.permits }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Resolver) resolve(ctx context.Context, data []byte) (*Resolved, error) {
	if batchCircuit(data) {
		return r.resolveBatch(ctx, data)
	}
	finishDecode := timing.FromContext(ctx).Start("indexer_decode")
	resolution, err := decode(data)
	finishDecode()
	if err != nil {
		return nil, err
	}
	return resolution(ctx, r)
}

// ResolvePrepared fetches and binds the tree paths of a checked request.
func (r *Resolver) ResolvePrepared(ctx context.Context, request Request, prepared *Prepared) (*Resolved, error) {
	if len(prepared.Inputs) != len(request.Inputs) {
		return nil, failure("indexer_prepared_input_count_mismatch", "prepared input count mismatch")
	}
	trace := timing.FromContext(ctx)
	finishAdmission := trace.Start("indexer_admission")
	defer finishAdmission()
	release, err := r.Admit(ctx)
	if err != nil {
		return nil, causedFailure("indexer_admission_canceled", "indexer preparation admission canceled", err)
	}
	defer release()
	finishAdmission()
	finishFetch := trace.Start("indexer_fetch")
	defer finishFetch()
	proofs := make([]treeProofs, len(request.Trees))
	for index, input := range request.Inputs {
		if prepared.Inputs[index].Disabled {
			continue
		}
		group := &proofs[input.TreeSlot]
		group.inputs = append(group.inputs, index)
		if input.Commitment != nil {
			group.realInputs = append(group.realInputs, index)
		}
	}
	for _, group := range proofs {
		if len(group.inputs) == 0 && !prepared.EmptyTrees {
			return nil, failure("indexer_input_tree_has_no_real_spend", "input tree has no real spend")
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// 1. Fetch one nullifier snapshot per tree for real and dummy inputs together.
	tasks, taskContext := errgroup.WithContext(ctx)
	if prepared.Fetch != nil {
		tasks.Go(recovered(func() error { return prepared.Fetch(taskContext, r) }))
	}
	for treeIndex, tree := range request.Trees {
		group := &proofs[treeIndex]
		leaves := make([]Hash, len(group.realInputs))
		for index, input := range group.realInputs {
			leaves[index] = *request.Inputs[input].Commitment
		}
		nullifiers := make([]Hash, len(group.inputs))
		for index, input := range group.inputs {
			prepared.Inputs[input].Nullifier.FillBytes(nullifiers[index][:])
		}
		if len(leaves) != 0 {
			tasks.Go(recovered(func() error {
				data, err := r.call(taskContext, proofQuery{Method: "getMerkleProofs", Tree: tree.Address, Leaves: leaves})
				if err != nil {
					return err
				}
				if json.Unmarshal(data, &group.state) != nil {
					return failure("indexer_invalid_state_proof_response", "invalid state proof response")
				}
				if group.state.Context.Slot < request.MinContextSlot {
					return notReady("indexer_state_context_slot_not_reached")
				}
				return nil
			}))
		}
		if len(nullifiers) != 0 {
			tasks.Go(recovered(func() error {
				data, err := r.call(taskContext, proofQuery{Method: "getNonInclusionProofs", Tree: tree.Address, Leaves: nullifiers})
				if err != nil {
					return err
				}
				if json.Unmarshal(data, &group.exclusion) != nil {
					return failure("indexer_invalid_nullifier_proof_response", "invalid nullifier proof response")
				}
				if group.exclusion.Context.Slot < request.MinContextSlot {
					return notReady("indexer_nullifier_context_slot_not_reached")
				}
				return nil
			}))
		}
	}
	if err := tasks.Wait(); err != nil {
		return nil, err
	}
	finishFetch()
	finishValidate := trace.Start("indexer_validate")
	defer finishValidate()
	// 2. Bind every returned path to its requested leaf before completing the inputs.
	resolution := &common.ProofResolution{Trees: make([]common.ResolvedTree, len(request.Trees))}
	slots := make([]common.TreeSlotParams, 5)
	for index := range slots {
		slots[index] = common.TreeSlotParams{ID: new(big.Int), UtxoRoot: new(big.Int), NullifierRoot: new(big.Int)}
	}
	for treeIndex, tree := range request.Trees {
		group := &proofs[treeIndex]
		if len(group.state.Proofs) != len(group.realInputs) || len(group.exclusion.Proofs) != len(group.inputs) {
			return nil, failure("indexer_proof_count_mismatch", "indexer proof count mismatch")
		}
		stateRoot := stateProof{RootIndex: ^uint16(0)}
		if len(group.state.Proofs) != 0 {
			stateRoot = group.state.Proofs[0]
		}
		var nullifierRoot nullifierProof
		if fallback := tree.Fallback; fallback != nil {
			state, _ := common.FeFromHex(fallback.UtxoRoot)
			exclusion, _ := common.FeFromHex(fallback.NullifierRoot)
			if len(group.state.Proofs) == 0 {
				stateRoot.Root, _ = HashField(state)
				stateRoot.RootIndex = fallback.UtxoRootIndex
			}
			nullifierRoot.Root, _ = HashField(exclusion)
			nullifierRoot.RootIndex = fallback.NullifierRootIndex
		}
		if len(group.exclusion.Proofs) != 0 {
			nullifierRoot = group.exclusion.Proofs[0]
		}
		states := make(map[int]*stateProof, len(group.realInputs))
		for index, input := range group.realInputs {
			proof := &group.state.Proofs[index]
			if proof.Leaf != *request.Inputs[input].Commitment || proof.MerkleContext.Tree != tree.Address || proof.MerkleContext.TreeType != 1 || proof.Root != stateRoot.Root || proof.RootIndex != stateRoot.RootIndex || proof.RootSeq != stateRoot.RootSeq || len(proof.Path) != 32 {
				return nil, failure("indexer_state_proof_binding_mismatch", "state proof binding mismatch")
			}
			if err := VerifyPath(proof.Leaf, proof.Path, proof.LeafIndex, proof.Root); err != nil {
				return nil, err
			}
			states[input] = proof
		}
		for index, input := range group.inputs {
			proof := group.exclusion.Proofs[index]
			expected, err := HashField(prepared.Inputs[input].Nullifier)
			if err != nil || proof.Leaf != expected || proof.MerkleContext.Tree != tree.Address || proof.MerkleContext.TreeType != 2 || proof.Root != nullifierRoot.Root || proof.RootIndex != nullifierRoot.RootIndex || proof.RootSeq != nullifierRoot.RootSeq || len(proof.Path) != 40 {
				return nil, failure("indexer_nullifier_proof_binding_mismatch", "nullifier proof binding mismatch")
			}
			low, err := proof.LowElement.Field()
			if err != nil {
				return nil, err
			}
			high, err := proof.HighElement.Field()
			if err != nil || low.Cmp(prepared.Inputs[input].Nullifier) >= 0 || high.Cmp(prepared.Inputs[input].Nullifier) <= 0 {
				return nil, failure("indexer_invalid_nullifier_exclusion_range", "invalid nullifier exclusion range")
			}
			leaf, err := prooftranscript.HashFields([]*big.Int{low, high})
			if err != nil {
				return nil, err
			}
			leafHash, err := HashField(leaf)
			if err != nil {
				return nil, err
			}
			if err := VerifyPath(leafHash, proof.Path, proof.LowElementIndex, proof.Root); err != nil {
				return nil, err
			}
			prepared.Inputs[input].apply(states[input], proof)
		}
		slots[treeIndex] = common.TreeSlotParams{ID: new(big.Int).SetUint64(uint64(tree.ID)), UtxoRoot: new(big.Int).SetBytes(stateRoot.Root[:]), NullifierRoot: new(big.Int).SetBytes(nullifierRoot.Root[:])}
		resolution.Trees[treeIndex] = common.ResolvedTree{Tree: tree.Address, ID: tree.ID, UtxoRoot: stateRoot.Root.hex(), NullifierRoot: nullifierRoot.Root.hex(), UtxoRootIndex: stateRoot.RootIndex, NullifierRootIndex: nullifierRoot.RootIndex}
	}
	// 3. Insert the resolved tree commitment into the circuit's public transcript.
	hashes := make([]*big.Int, len(slots))
	for index, slot := range slots {
		hashes[index], err = prooftranscript.HashFields([]*big.Int{slot.ID, slot.UtxoRoot, slot.NullifierRoot})
		if err != nil {
			return nil, classifyFailure("indexer_tree_slot_hash_failed", "cannot hash resolved tree slot", err)
		}
	}
	treeHash, err := prooftranscript.RightHashChain(hashes)
	if err != nil {
		return nil, classifyFailure("indexer_tree_hash_failed", "cannot hash resolved trees", err)
	}
	public, err := common.FeFromHexSlice(request.PublicInputs)
	if err != nil {
		return nil, failure("indexer_invalid_public_input", "invalid public input")
	}
	if prepared.Statement != nil {
		*prepared.Hash, err = prepared.Statement(public, treeHash)
	} else {
		transcript := append([]*big.Int{}, public[:2]...)
		transcript = append(transcript, treeHash)
		transcript = append(transcript, public[2:]...)
		*prepared.Hash, err = prooftranscript.HashChain4(transcript)
	}
	if err != nil {
		return nil, classifyFailure("indexer_statement_hash_failed", "cannot hash resolved statement", err)
	}
	*prepared.Slots = slots
	resolution.PublicInputHash = common.FeHex(*prepared.Hash)
	payload, err := prepared.Value.MarshalJSON()
	if err != nil {
		return nil, failure("indexer_encode_resolved_inputs", "cannot encode resolved inputs")
	}
	return &Resolved{Payload: payload, Resolution: resolution}, nil
}

// DecodeEnvelope rejects unknown fields and trailing data.
func DecodeEnvelope(data []byte, request any) error {
	if len(data) > 1<<20 {
		return failure("indexer_request_too_large", "indexed request exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(request); err != nil {
		return failure("indexer_invalid_indexed_request_json", "invalid indexed request JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return failure("indexer_request_trailing_json", "indexed request contains trailing JSON")
	}
	return nil
}

func requestCircuit(data []byte) common.CircuitType {
	var meta struct {
		Circuit common.CircuitType `json:"circuitType"`
	}
	if json.Unmarshal(data, &meta) != nil {
		return ""
	}
	return meta.Circuit
}

func VerifyPath(leaf Hash, path []Hash, index uint64, root Hash) error {
	if len(path) > 63 || index >= uint64(1)<<len(path) {
		return failure("indexer_invalid_proof_path_index", "invalid proof path index")
	}
	hash, err := leaf.Field()
	if err != nil {
		return err
	}
	for level, sibling := range path {
		value, err := sibling.Field()
		if err != nil {
			return err
		}
		pair := []*big.Int{hash, value}
		if index>>level&1 != 0 {
			pair[0], pair[1] = pair[1], pair[0]
		}
		hash, err = prooftranscript.HashFields(pair)
		if err != nil {
			return err
		}
	}
	if !bytes.Equal(hash.FillBytes(make([]byte, 32)), root[:]) {
		return failure("indexer_proof_root_mismatch", "proof root mismatch")
	}
	return nil
}

// errgroup does not recover task panics.
func recovered(task func() error) func() error {
	return func() (err error) {
		defer func() {
			if recover() != nil {
				err = failure("indexer_task_panicked", "indexed task panicked")
			}
		}()
		return task()
	}
}
