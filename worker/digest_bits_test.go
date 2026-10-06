package worker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/zilong-dai/gnark/backend/groth16"
	bn254 "github.com/zilong-dai/gnark/backend/groth16/bn254"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

func digestIdentityFixtureFor(t *testing.T, artifact uint32) string {
	t.Helper()
	var common types.CommonCircuitDataRaw
	width, err := digestBitsWidth(artifact)
	if err != nil {
		t.Fatalf("unsupported fixture artifact %d", artifact)
	}
	common.NumPublicInputs = uint64(width)
	common.Config.NumWires = 3
	common.Config.NumRoutedWires = 2
	common.Config.NumChallenges = 1
	common.NumConstants = 1
	common.QuotientDegreeFactor = 1
	common.FriParams.DegreeBits = 4
	common.FriParams.Config.RateBits = 1
	common.FriParams.Config.NumQueryRounds = 2
	common.FriParams.ReductionArityBits = []uint64{2}
	common.Config.FriConfig.ReductionStrategy.ConstantArityBits = []uint64{2, 2}
	common.FriParams.Config.ReductionStrategy.ConstantArityBits = []uint64{2, 2}
	common.Gates = []string{}
	common.SelectorsInfo.SelectorIndices = []uint64{}
	common.SelectorsInfo.Groups = []struct {
		Start uint64 `json:"start"`
		End uint64 `json:"end"`
	}{}
	common.KIs = []uint64{}
	commonJSON, err := json.Marshal(common)
	if err != nil { t.Fatal(err) }
	identity := DigestBitsIdentity{Schema: 1, Mode: "DigestBits", Artifact: artifact,
		NodeSource: strings.Repeat("1", 40), NativeSource: strings.Repeat("2", 40),
		Plonky2Source: strings.Repeat("3", 40), WrapperSource: strings.Repeat("4", 40),
		NormalizerFingerprint: []uint64{1, 2, 3, 4}, NormalizerCommon: "01", NormalizerVerifier: "02",
		FinalCommonJSON: string(commonJSON), FinalVerifierJSON: `{"constants_sigmas_cap":["1"],"circuit_digest":"2"}`}
	data, err := json.Marshal(identity)
	if err != nil { t.Fatal(err) }
	return string(data)

}

func digestIdentityFixture(t *testing.T) string { return digestIdentityFixtureFor(t, 1) }

func TestDigestBitsHalves(t *testing.T) {
	bits := make([]uint64, 256)
	bits[0], bits[127], bits[129], bits[255] = 1, 1, 1, 1
	halves, err := digestBitsHalves(bits)
	if err != nil { t.Fatal(err) }
	if len(halves) != 2 { t.Fatalf("256 bits produced %d halves", len(halves)) }
	for i, shift := range []uint{127, 126} {
		want := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), shift), big.NewInt(1))
		if halves[i].Cmp(want) != 0 { t.Fatalf("half %d: got %s want %s", i, halves[i], want) }
	}
	wide := make([]uint64, 768)
	for half, at := range []int{0, 128, 256, 384, 512, 640} { wide[at], wide[at+127] = 1, 1; _ = half }
	wideHalves, err := digestBitsHalves(wide)
	if err != nil { t.Fatal(err) }
	if len(wideHalves) != 6 { t.Fatalf("768 bits produced %d halves", len(wideHalves)) }
	wantWide := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	for i, half := range wideHalves {
		if half.Cmp(wantWide) != 0 { t.Fatalf("wide half %d: got %s", i, half) }
	}
	for _, width := range []int{0, 128, 255, 257, 512, 767, 769, 1024} {
		if _, err := digestBitsHalves(make([]uint64, width)); err == nil { t.Fatalf("accepted width %d", width) }
	}
	bits[200] = 2
	if _, err := digestBitsHalves(bits); err == nil { t.Fatal("accepted non-Boolean bit") }
	wide[700] = 2
	if _, err := digestBitsHalves(wide); err == nil { t.Fatal("accepted non-Boolean wide bit") }
}

type digestFoldingCircuit struct {
	Public []frontend.Variable `gnark:",public"`
	Bits []gl.Variable
}

func (c *digestFoldingCircuit) Define(api frontend.API) error {
	return constrainDigestBits(api, c.Public, c.Bits)
}

func TestDigestBitsConstraints(t *testing.T) {
	checkWidth := func(bits []uint64) {
		t.Helper()
		halves, err := digestBitsHalves(bits)
		if err != nil { t.Fatal(err) }
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &digestFoldingCircuit{Public: make([]frontend.Variable, len(halves)), Bits: make([]gl.Variable, len(bits))})
		if err != nil { t.Fatal(err) }
		assignment := digestFoldingCircuit{Public: make([]frontend.Variable, len(halves)), Bits: make([]gl.Variable, len(bits))}
		for i, half := range halves { assignment.Public[i] = half }
		for i, bit := range bits { assignment.Bits[i] = gl.NewVariable(bit) }
		check := func(wantValid bool) {
			t.Helper()
			w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
			if err != nil { t.Fatal(err) }
			if err := ccs.IsSolved(w); (err == nil) != wantValid { t.Fatalf("valid=%v: %v", wantValid, err) }
		}
		check(true)
		assignment.Public[0], assignment.Public[1] = assignment.Public[1], assignment.Public[0]
		check(false)
		assignment.Public[0], assignment.Public[1] = halves[0], halves[1]
		assignment.Bits[20] = gl.NewVariable(2)
		check(false)
	}
	two := make([]uint64, 256)
	two[0], two[255] = 1, 1
	checkWidth(two)
	six := make([]uint64, 768)
	six[0], six[767] = 1, 1
	checkWidth(six)
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &digestFoldingCircuit{Public: make([]frontend.Variable, 2), Bits: make([]gl.Variable, 768)}); err == nil { t.Fatal("compiled two public inputs over 768 bits") }
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &digestFoldingCircuit{Public: make([]frontend.Variable, 6), Bits: make([]gl.Variable, 256)}); err == nil { t.Fatal("compiled six public inputs over 256 bits") }
}

func TestDigestIdentityStrictness(t *testing.T) {
	encoded := digestIdentityFixture(t)
	identity, hash, failure := readDigestIdentity(1, encoded)
	if failure != nil { t.Fatal(failure) }
	if _, _, failure := readDigestIdentity(2, encoded); failure == nil { t.Fatal("accepted swapped artifact") }
	for _, bad := range []string{encoded + `{}`, strings.Replace(encoded, `"schema":1`, `"schema":1,"schema":1`, 1), strings.Replace(encoded, `"schema":1`, `"extra":1,"schema":1`, 1), strings.Replace(encoded, `"mode":"DigestBits"`, `"mode":null`, 1)} {
		if _, _, failure := readDigestIdentity(1, bad); failure == nil { t.Fatalf("accepted malformed identity %s", bad) }
	}
	identity.FinalVerifierJSON = `{"constants_sigmas_cap":["1"],"circuit_digest":"3"}`
	changed, err := json.Marshal(identity)
	if err != nil { t.Fatal(err) }
	_, changedHash, failure := readDigestIdentity(1, string(changed))
	if failure != nil { t.Fatal(failure) }
	if hash == changedHash { t.Fatal("final verifier does not change identity") }
	identity.NormalizerFingerprint[0] = 0xffffffff00000001
	changed, err = json.Marshal(identity)
	if err != nil { t.Fatal(err) }
	if _, _, failure := readDigestIdentity(1, string(changed)); failure == nil { t.Fatal("accepted noncanonical Felt") }
}

func TestDigestIdentitySeparatesAggregateFamilies(t *testing.T) {
	hashes := make(map[string]bool)
	for _, artifact := range []uint32{1, 2, 3} {
		identity, _, failure := readDigestIdentity(artifact, digestIdentityFixtureFor(t, artifact))
		if failure != nil { t.Fatal(failure) }
		encoded, err := json.Marshal(identity)
		if err != nil { t.Fatal(err) }
		_, hash, failure := readDigestIdentity(artifact, string(encoded))
		if failure != nil { t.Fatal(failure) }
		if hashes[hash] { t.Fatal("artifact family did not change setup identity") }
		hashes[hash] = true
		for _, other := range []uint32{0, 1, 2, 3, 4} {
			if other == artifact { continue }
			if _, _, failure := readDigestIdentity(other, string(encoded)); failure == nil { t.Fatal("accepted mismatched artifact family") }
		}
		var common types.CommonCircuitDataRaw
		if err := json.Unmarshal([]byte(identity.FinalCommonJSON), &common); err != nil { t.Fatal(err) }
		otherArtifact := uint32(1)
		if artifact == 1 { otherArtifact = 2 }
		crossedWidth, err := digestBitsWidth(otherArtifact)
		if err != nil { t.Fatal(err) }
		common.NumPublicInputs = uint64(crossedWidth)
		commonJSON, err := json.Marshal(common)
		if err != nil { t.Fatal(err) }
		identity.FinalCommonJSON = string(commonJSON)
		crossed, err := json.Marshal(identity)
		if err != nil { t.Fatal(err) }
		if _, _, failure := readDigestIdentity(artifact, string(crossed)); failure == nil { t.Fatal("accepted crossed digest width") }
	}
	identity, _, failure := readDigestIdentity(1, digestIdentityFixture(t))
	if failure != nil { t.Fatal(failure) }
	for _, artifact := range []uint32{0, 4} {
		identity.Artifact = artifact
		encoded, err := json.Marshal(identity)
		if err != nil { t.Fatal(err) }
		if _, _, failure := readDigestIdentity(artifact, string(encoded)); failure == nil { t.Fatal("accepted unsupported artifact family") }
	}
}

func TestDigestSetupShapeWithoutProof(t *testing.T) {
	for _, artifact := range []uint32{1, 2, 3} {
		identity, _, failure := readDigestIdentity(artifact, digestIdentityFixtureFor(t, artifact))
		if failure != nil { t.Fatal(failure) }
		circuit, err := buildDigestCircuit(identity)
		if err != nil { t.Fatal(err) }
		wantBits, err := digestBitsWidth(artifact)
		if err != nil { t.Fatal(err) }
		wantPublic := wantBits / 128
		if len(circuit.OriginalPublicInputs) != wantBits || len(circuit.PublicInputs) != wantPublic { t.Fatalf("artifact %d has width %d/%d", artifact, len(circuit.OriginalPublicInputs), len(circuit.PublicInputs)) }
		if artifact == 1 {
			if len(circuit.Proof.OpeningProof.FinalPoly.Coeffs) != 4 || len(circuit.Proof.OpeningProof.QueryRoundProofs) != 2 { t.Fatal("incorrect final polynomial/query shape") }
			query := circuit.Proof.OpeningProof.QueryRoundProofs[0]
			if len(query.InitialTreesProof.EvalsProofs[0].Elements) != 3 || len(query.InitialTreesProof.EvalsProofs[0].MerkleProof.Siblings) != 5 || len(query.Steps[0].Evals) != 4 || len(query.Steps[0].MerkleProof.Siblings) != 3 { t.Fatal("incorrect initial/reduction proof shape") }
		}
	}
}
func minimalDigestProofJSON(t *testing.T, width int) string {
	t.Helper()
	ext := func(n int) [][]uint64 { out := make([][]uint64, n); for i := range out { out[i] = []uint64{0, 0} }; return out }
	siblings := func(n int) []string { out := make([]string, n); for i := range out { out[i] = "0" }; return out }
	eval := func(elements, height int) []interface{} {
		return []interface{}{make([]uint64, elements), map[string]interface{}{"siblings": siblings(height)}}
	}
	step := func(evals, height int) map[string]interface{} {
		return map[string]interface{}{"evals": ext(evals), "merkle_proof": map[string]interface{}{"siblings": siblings(height)}}
	}
	query := map[string]interface{}{
		"initial_trees_proof": map[string]interface{}{"evals_proofs": []interface{}{eval(3, 5), eval(3, 5), eval(2, 5), eval(1, 5)}},
		"steps": []interface{}{step(4, 3)},
	}
	raw := map[string]interface{}{
		"proof": map[string]interface{}{
			"wires_cap": siblings(1), "plonk_zs_partial_products_cap": siblings(1), "quotient_polys_cap": siblings(1),
			"openings": map[string]interface{}{
				"constants": ext(1), "plonk_sigmas": ext(2), "wires": ext(3), "plonk_zs": ext(1), "plonk_zs_next": ext(1),
				"partial_products": ext(0), "quotient_polys": ext(1),
			},
			"opening_proof": map[string]interface{}{
				"commit_phase_merkle_caps": []interface{}{siblings(1)}, "query_round_proofs": []interface{}{query, query},
				"final_poly": map[string]interface{}{"coeffs": ext(4)}, "pow_witness": 0,
			},
		},
		"public_inputs": make([]uint64, width),
	}
	data, err := json.Marshal(raw)
	if err != nil { t.Fatal(err) }
	return string(data)
}

func TestRewardPublicationWidth(t *testing.T) {
	const reward uint32 = 3
	narrow := digestIdentityFixtureFor(t, reward)
	var identity DigestBitsIdentity
	if err := json.Unmarshal([]byte(narrow), &identity); err != nil { t.Fatal(err) }
	var common types.CommonCircuitDataRaw
	if err := json.Unmarshal([]byte(identity.FinalCommonJSON), &common); err != nil { t.Fatal(err) }
	common.NumPublicInputs = 256
	commonJSON, err := json.Marshal(common)
	if err != nil { t.Fatal(err) }
	identity.FinalCommonJSON = string(commonJSON)
	rejected, err := json.Marshal(identity)
	if err != nil { t.Fatal(err) }
	if _, _, failure := readDigestIdentity(reward, string(rejected)); failure == nil { t.Fatal("accepted reward publication at 256 bits") }
	if _, err := buildDigestCircuit(&identity); err == nil { t.Fatal("built reward circuit at 256 bits") }
	if _, _, err := GenerateDigestBitsProof(reward, narrow, minimalDigestProofJSON(t, 256), t.TempDir()); err == nil { t.Fatal("proved reward publication at 256 bits") }
	if _, _, err := GenerateDigestBitsProof(reward, narrow, minimalDigestProofJSON(t, 768), t.TempDir()); err == nil { t.Fatal("proved reward publication without its pinned setup") }

	accepted, _, failure := readDigestIdentity(reward, narrow)
	if failure != nil { t.Fatal(failure) }
	if err := json.Unmarshal([]byte(accepted.FinalCommonJSON), &common); err != nil || common.NumPublicInputs != 768 { t.Fatalf("reward common width %d", common.NumPublicInputs) }
	circuit, err := buildDigestCircuit(accepted)
	if err != nil { t.Fatal(err) }
	if len(circuit.OriginalPublicInputs) != 768 || len(circuit.PublicInputs) != 6 { t.Fatalf("reward circuit width %d/%d", len(circuit.OriginalPublicInputs), len(circuit.PublicInputs)) }
	bits := make([]uint64, 768)
	for half := range 6 { bits[half*128+half] = 1 }
	halves, err := digestBitsHalves(bits)
	if err != nil || len(halves) != 6 { t.Fatalf("reward halves: %d %v", len(halves), err) }
	for i, half := range halves {
		want := new(big.Int).Lsh(big.NewInt(1), uint(127-i))
		if half.Cmp(want) != 0 { t.Fatalf("reward half %d: got %s want %s", i, half, want) }
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &digestFoldingCircuit{Public: make([]frontend.Variable, 6), Bits: make([]gl.Variable, 768)})
	if err != nil { t.Fatal(err) }
	assignment := digestFoldingCircuit{Public: make([]frontend.Variable, 6), Bits: make([]gl.Variable, 768)}
	for i, half := range halves { assignment.Public[i] = half }
	for i, bit := range bits { assignment.Bits[i] = gl.NewVariable(bit) }
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil { t.Fatal(err) }
	if err := ccs.IsSolved(witness); err != nil { t.Fatal(err) }
	assignment.Public[0], assignment.Public[1] = assignment.Public[1], assignment.Public[0]
	swapped, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil { t.Fatal(err) }
	if err := ccs.IsSolved(swapped); err == nil { t.Fatal("accepted swapped reward halves") }
}

func TestDigestArtifactTampering(t *testing.T) {
	identityJSON := digestIdentityFixture(t)
	_, hash, failure := readDigestIdentity(1, identityJSON)
	if failure != nil { t.Fatal(failure) }
	dir := t.TempDir()
	manifest := digestBitsManifest{Schema: 1, IdentityHash: hash}
	for _, name := range digestBitsFileNames {
		data := []byte("fixture:" + name)
		if name == "identity.json" { data = []byte(identityJSON) }
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil { t.Fatal(err) }
		digest := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, digestBitsFile{name, hex.EncodeToString(digest[:])})
	}
	data, err := json.Marshal(manifest)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil { t.Fatal(err) }
	if _, err := readDigestArtifacts(dir, hash, 1); err != nil { t.Fatal(err) }
	if _, err := readDigestArtifacts(dir, strings.Repeat("0", 64), 1); err == nil { t.Fatal("accepted different identity") }
	if err := os.WriteFile(filepath.Join(dir, "pk_groth16.bin"), []byte("changed"), 0600); err != nil { t.Fatal(err) }
	if _, err := readDigestArtifacts(dir, hash, 1); err == nil { t.Fatal("accepted changed key after prior load") }
}

func TestDigestProofEncoding(t *testing.T) {
	for _, value := range []interface{}{[][]uint64{{1}}, [][]uint64{{1, 2, 3}}, uint64(0xffffffff00000001), "01", "-1"} {
		if err := validateDigestProofValue(reflect.ValueOf(value)); err == nil { t.Fatalf("accepted %v", value) }
	}
}

func publicWitness(t *testing.T, count int) witness.Witness {
	t.Helper()
	values := make(chan any)
	go func() {
		for i := 0; i < count; i++ { values <- big.NewInt(int64(i + 1)) }
		close(values)
	}()
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil { t.Fatal(err) }
	if err := w.Fill(count, 0, values); err != nil { t.Fatal(err) }
	public, err := w.Public()
	if err != nil { t.Fatal(err) }
	return public
}

func proofJSONWithWords(t *testing.T, words []string) []byte {
	t.Helper()
	g1 := strings.Repeat("0", 128)
	g2 := strings.Repeat("0", 256)
	body := map[string]interface{}{"pi_a": [2]string{g1[:64], g1[64:]}, "pi_b": [2][2]string{{g2[:64], g2[64:128]}, {g2[128:192], g2[192:]}}, "pi_c": [2]string{g1[:64], g1[64:]}, "Commitments": "", "CommitmentPok": g1, "public_inputs": words}
	data, err := json.Marshal(body)
	if err != nil { t.Fatal(err) }
	return data
}

func TestDigestProofJSONWitnessCount(t *testing.T) {
	for _, count := range []int{2, 6} {
		proof := &G16ProofWithPublicInputs{Proof: groth16.NewProof(ecc.BN254).(*bn254.Proof), PublicInputs: publicWitness(t, count)}
		encoded, err := json.Marshal(proof)
		if err != nil { t.Fatal(err) }
		decoded := NewG16ProofWithPublicInputs()
		if err := json.Unmarshal(encoded, decoded); err != nil { t.Fatalf("count %d: %v", count, err) }
		original, err := proof.PublicInputs.MarshalBinary()
		if err != nil { t.Fatal(err) }
		round, err := decoded.PublicInputs.MarshalBinary()
		if err != nil || !reflect.DeepEqual(original, round) || binary.BigEndian.Uint32(original[:4]) != uint32(count) || binary.BigEndian.Uint32(original[4:8]) != 0 || binary.BigEndian.Uint32(original[8:12]) != uint32(count) { t.Fatalf("count %d witness bytes changed", count) }
		var payload struct { PublicInputs []string `json:"public_inputs"` }
		if err := json.Unmarshal(encoded, &payload); err != nil || len(payload.PublicInputs) != count { t.Fatalf("count %d JSON width changed", count) }
	}
	words := func(n int) []string { out := make([]string, n); for i := range out { out[i] = fmt.Sprintf("%064x", i+0xab) }; return out }
	for _, count := range []int{2, 6} {
		if err := NewG16ProofWithPublicInputs().UnmarshalJSON(proofJSONWithWords(t, words(count))); err != nil { t.Fatalf("valid %d-word fixture rejected: %v", count, err) }
	}
	for _, bad := range [][]string{words(0), words(1), words(3), words(5), words(7)} {
		if err := NewG16ProofWithPublicInputs().UnmarshalJSON(proofJSONWithWords(t, bad)); err == nil { t.Fatalf("accepted %d public inputs", len(bad)) }
	}
	uppercase := words(2)
	uppercase[0] = strings.ToUpper(uppercase[0])
	short := words(2)
	short[1] = short[1][:63]
	malformed := words(2)
	malformed[1] = strings.Repeat("0", 63) + "g"
	modulus := new(big.Int).Set(fr.Modulus())
	over := words(6)
	over[5] = fmt.Sprintf("%064x", modulus)
	for _, bad := range [][]string{uppercase, short, malformed, over} {
		if err := NewG16ProofWithPublicInputs().UnmarshalJSON(proofJSONWithWords(t, bad)); err == nil { t.Fatal("accepted malformed public input word") }
	}
}

func TestDigestFailedPublicationLeavesDestinationAbsent(t *testing.T) {
	parent := t.TempDir()
	destination := filepath.Join(parent, "DepositAggregate")
	injected := errors.New("injected proving-key write failure")
	err := publishDigestArtifacts(1, strings.Repeat("0", 64), destination, func(name string, w io.Writer) error {
		if name == "pk_groth16.bin" { return injected }
		_, err := io.WriteString(w, "partial setup bytes")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), injected.Error()) { t.Fatalf("expected injected publication failure, got %v", err) }
	if _, err := os.Lstat(destination); !os.IsNotExist(err) { t.Fatalf("failed publication left destination: %v", err) }
	entries, err := os.ReadDir(parent)
	if err != nil { t.Fatal(err) }
	if len(entries) != 0 { t.Fatalf("failed publication left temporary artifacts: %v", entries) }
}

func TestDigestPublicationSuccessAndNoReplace(t *testing.T) {
	identityJSON := digestIdentityFixture(t)
	_, hash, failure := readDigestIdentity(1, identityJSON)
	if failure != nil { t.Fatal(failure) }
	parent := t.TempDir()
	destination := filepath.Join(parent, "DepositAggregate")
	// Publication treats key payloads as opaque bytes; no cryptographic setup is exercised.
	write := func(name string, w io.Writer) error {
		data := "publication payload:" + name
		if name == "identity.json" { data = identityJSON }
		_, err := io.WriteString(w, data)
		return err
	}
	if err := publishDigestArtifacts(1, hash, destination, write); err != nil { t.Fatal(err) }
	files, err := readDigestArtifacts(destination, hash, 1)
	if err != nil { t.Fatal(err) }
	if string(files["identity.json"]) != identityJSON || string(files["pk_groth16.bin"]) != "publication payload:pk_groth16.bin" { t.Fatal("published bytes changed") }
	if err := publishDigestArtifacts(1, hash, destination, func(name string, w io.Writer) error {
		if name == "identity.json" { _, err := io.WriteString(w, identityJSON); return err }
		_, err := io.WriteString(w, "replacement payload")
		return err
	}); err == nil { t.Fatal("replaced existing destination") }
	after, err := readDigestArtifacts(destination, hash, 1)
	if err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(files, after) { t.Fatal("existing destination changed after refused publication") }
	entries, err := os.ReadDir(parent)
	if err != nil { t.Fatal(err) }
	if len(entries) != 1 || entries[0].Name() != "DepositAggregate" { t.Fatalf("unexpected publication leftovers: %v", entries) }
}

func TestDigestPublicationParentSyncFailurePreservesDestination(t *testing.T) {
	identityJSON := digestIdentityFixture(t)
	_, hash, failure := readDigestIdentity(1, identityJSON)
	if failure != nil { t.Fatal(failure) }
	parent := t.TempDir()
	destination := filepath.Join(parent, "DepositAggregate")
	injected := errors.New("injected final directory sync failure")
	err := publishDigestArtifactsWithParentSync(1, hash, destination, func(name string, w io.Writer) error {
		data := "publication payload:" + name
		if name == "identity.json" { data = identityJSON }
		_, err := io.WriteString(w, data)
		return err
	}, func(path string) error {
		if path != parent { t.Fatalf("syncing unexpected parent %s", path) }
		if _, err := readDigestArtifacts(destination, hash, 1); err != nil { t.Fatalf("sync ran before complete publication: %v", err) }
		return injected
	})
	if err == nil || !strings.Contains(err.Error(), injected.Error()) { t.Fatalf("expected durability failure, got %v", err) }
	if _, err := readDigestArtifacts(destination, hash, 1); err != nil { t.Fatalf("published destination removed after sync failure: %v", err) }
	entries, err := os.ReadDir(parent)
	if err != nil { t.Fatal(err) }
	if len(entries) != 1 || entries[0].Name() != "DepositAggregate" { t.Fatalf("unexpected publication leftovers: %v", entries) }
}

func TestFinalizeIdentityBindsChainListAndVerifier(t *testing.T) {
	digest, _, failure := readDigestIdentity(1, digestIdentityFixture(t))
	if failure != nil { t.Fatal(failure) }
	var common types.CommonCircuitDataRaw
	if err := json.Unmarshal([]byte(digest.FinalCommonJSON), &common); err != nil { t.Fatal(err) }
	common.NumPublicInputs = (144+72*2)*8
	commonJSON, err := json.Marshal(common)
	if err != nil { t.Fatal(err) }
	identity := FinalizeIdentity{Schema: 1, ChainIndices: []uint16{0, 255}, FinalCommonJSON: string(commonJSON), FinalVerifierJSON: digest.FinalVerifierJSON}
	encode := func() string { data, err := json.Marshal(identity); if err != nil { t.Fatal(err) }; return string(data) }
	_, original, err := readFinalizeIdentity(encode())
	if err != nil { t.Fatal(err) }
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(encode()), 0600); err != nil { t.Fatal(err) }
	if _, err := ReadFinalizeSetupIdentity(dir); err == nil { t.Fatal("accepted loose identity without checked setup manifest") }
	listHash := finalizeChainListHash(&identity)
	identity.ChainIndices[1] = 254
	_, changed, err := readFinalizeIdentity(encode())
	if err != nil || changed == original { t.Fatal("chain-list substitution retained identity") }
	if reflect.DeepEqual(listHash, finalizeChainListHash(&identity)) { t.Fatal("chain-list substitution retained getter") }
	identity.ChainIndices[1] = 255
	identity.FinalVerifierJSON = `{"constants_sigmas_cap":["1"],"circuit_digest":"3"}`
	_, changed, err = readFinalizeIdentity(encode())
	if err != nil || changed == original { t.Fatal("source verifier substitution retained identity") }
	for _, indices := range [][]uint16{nil, {0}, {0, 0}, {255, 0}, {0, 256}} {
		identity.ChainIndices = indices
		if _, _, err := readFinalizeIdentity(encode()); err == nil { t.Fatal("accepted invalid list or incompatible PI width") }
	}
	identity.ChainIndices = make([]uint16, 256)
	for i := range identity.ChainIndices { identity.ChainIndices[i] = uint16(i) }
	common.NumPublicInputs = (144+72*256)*8
	commonJSON, err = json.Marshal(common)
	if err != nil { t.Fatal(err) }
	identity.FinalCommonJSON = string(commonJSON)
	if _, _, err := readFinalizeIdentity(encode()); err != nil { t.Fatal(err) }
}

func TestFinalizeExportRejectsMissingSetupIdentity(t *testing.T) {
	if _, err := ExportFinalizeVerifier(t.TempDir()); err == nil { t.Fatal("export accepted missing reviewed setup identity") }
}
