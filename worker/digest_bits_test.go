package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

func digestIdentityFixture(t *testing.T) string {
	t.Helper()
	var common types.CommonCircuitDataRaw
	common.NumPublicInputs = 256
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
	identity := DigestBitsIdentity{Schema: 1, Mode: "DigestBits", Artifact: 1,
		NodeSource: strings.Repeat("1", 40), NativeSource: strings.Repeat("2", 40),
		Plonky2Source: strings.Repeat("3", 40), WrapperSource: strings.Repeat("4", 40),
		NormalizerFingerprint: []uint64{1, 2, 3, 4}, NormalizerCommon: "01", NormalizerVerifier: "02",
		FinalCommonJSON: string(commonJSON), FinalVerifierJSON: `{"constants_sigmas_cap":["1"],"circuit_digest":"2"}`}
	data, err := json.Marshal(identity)
	if err != nil { t.Fatal(err) }
	return string(data)
}

func TestDigestBitsHalves(t *testing.T) {
	bits := make([]uint64, 256)
	bits[0], bits[127], bits[129], bits[255] = 1, 1, 1, 1
	halves, err := digestBitsHalves(bits)
	if err != nil { t.Fatal(err) }
	for i, shift := range []uint{127, 126} {
		want := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), shift), big.NewInt(1))
		if halves[i].Cmp(want) != 0 { t.Fatalf("half %d: got %s want %s", i, halves[i], want) }
	}
	for _, width := range []int{0, 255, 257} {
		if _, err := digestBitsHalves(make([]uint64, width)); err == nil { t.Fatalf("accepted width %d", width) }
	}
	bits[200] = 2
	if _, err := digestBitsHalves(bits); err == nil { t.Fatal("accepted non-Boolean bit") }
}

type digestFoldingCircuit struct {
	Public []frontend.Variable `gnark:",public"`
	Bits []gl.Variable
}

func (c *digestFoldingCircuit) Define(api frontend.API) error {
	return constrainDigestBits(api, c.Public, c.Bits)
}

func TestDigestBitsConstraints(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &digestFoldingCircuit{Public: make([]frontend.Variable, 2), Bits: make([]gl.Variable, 256)})
	if err != nil { t.Fatal(err) }
	bits := make([]uint64, 256)
	bits[0], bits[255] = 1, 1
	halves, err := digestBitsHalves(bits)
	if err != nil { t.Fatal(err) }
	assignment := digestFoldingCircuit{Public: []frontend.Variable{halves[0], halves[1]}, Bits: make([]gl.Variable, 256)}
	for i, bit := range bits { assignment.Bits[i] = gl.NewVariable(bit) }
	check := func(wantValid bool) {
		t.Helper()
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil { t.Fatal(err) }
		if err := ccs.IsSolved(w); (err == nil) != wantValid { t.Fatalf("valid=%v: %v", wantValid, err) }
	}
	check(true)
	assignment.Public[0], assignment.Public[1] = halves[1], halves[0]
	check(false)
	assignment.Public[0], assignment.Public[1] = halves[0], halves[1]
	assignment.Bits[20] = gl.NewVariable(2)
	check(false)
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

func TestDigestIdentitySeparatesBatchFamilies(t *testing.T) {
	identity, _, failure := readDigestIdentity(1, digestIdentityFixture(t))
	if failure != nil { t.Fatal(failure) }
	hashes := make(map[string]bool)
	for _, artifact := range []uint32{1, 2, 3} {
		identity.Artifact = artifact
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
	}
	for _, artifact := range []uint32{0, 4} {
		identity.Artifact = artifact
		encoded, err := json.Marshal(identity)
		if err != nil { t.Fatal(err) }
		if _, _, failure := readDigestIdentity(artifact, string(encoded)); failure == nil { t.Fatal("accepted unsupported artifact family") }
	}
}

func TestDigestSetupShapeWithoutProof(t *testing.T) {
	identity, _, failure := readDigestIdentity(1, digestIdentityFixture(t))
	if failure != nil { t.Fatal(failure) }
	circuit, err := buildDigestCircuit(identity)
	if err != nil { t.Fatal(err) }
	if len(circuit.Proof.OpeningProof.FinalPoly.Coeffs) != 4 || len(circuit.Proof.OpeningProof.QueryRoundProofs) != 2 { t.Fatal("incorrect final polynomial/query shape") }
	query := circuit.Proof.OpeningProof.QueryRoundProofs[0]
	if len(query.InitialTreesProof.EvalsProofs[0].Elements) != 3 || len(query.InitialTreesProof.EvalsProofs[0].MerkleProof.Siblings) != 5 || len(query.Steps[0].Evals) != 4 || len(query.Steps[0].MerkleProof.Siblings) != 3 { t.Fatal("incorrect initial/reduction proof shape") }
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
