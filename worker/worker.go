package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
	"golang.org/x/sys/unix"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/rs/zerolog"
	"github.com/zilong-dai/gnark/backend/groth16"
	groth16_bn254 "github.com/zilong-dai/gnark/backend/groth16/bn254"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
	csbls12381 "github.com/zilong-dai/gnark/constraint/bls12-381"
	csbn254 "github.com/zilong-dai/gnark/constraint/bn254"
	csolver "github.com/zilong-dai/gnark/constraint/solver"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/std/hash/sha3"
	"github.com/zilong-dai/gnark/std/math/uints"
	gosha3 "golang.org/x/crypto/sha3"
)

func fpHex(x *fp.Element) string {
	return fmt.Sprintf("%064x", x.BigInt(new(big.Int)))
}

type PreparedCircuit struct {
	PKey *groth16_bn254.ProvingKey
	VKey *groth16_bn254.VerifyingKey
	CCS  *constraint.ConstraintSystem
}

var prepCircuits = map[string]*PreparedCircuit{}
var prepCircuitsMu sync.Mutex

func Initialize(keystore_path string) {
	fmt.Println("Initializing...", time.Now().Format("2006-01-02 15:04:05"))
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var ccs constraint.ConstraintSystem
	var err error
	if !CheckKeysExist(keystore_path) {
		panic(fmt.Sprintf("keystore files are missing under %s; initialize expects an existing setup on disk", keystore_path))
	}

	ccs, err = ReadCircuit(ecc.BN254, filepath.Join(keystore_path, CIRCUIT_PATH))
	if err != nil {
		panic(err)
	}
	vk, err = ReadVerifyingKey(ecc.BN254, filepath.Join(keystore_path, VK_PATH))
	if err != nil {
		panic(err)
	}
	pk, err = ReadProvingKey(ecc.BN254, filepath.Join(keystore_path, PK_PATH))
	if err != nil {
		panic(err)
	}

	prepCircuitsMu.Lock()
	defer prepCircuitsMu.Unlock()
	prepCircuits[keystore_path] = &PreparedCircuit{
		CCS:  &ccs,
		PKey: pk.(*groth16_bn254.ProvingKey),
		VKey: vk.(*groth16_bn254.VerifyingKey),
	}
	fmt.Println("Initializing End...", time.Now().Format("2006-01-02 15:04:05"))
}

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:",secret"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	OriginalPublicInputs []gl.Variable `gnark:",secret"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData `gnark:",secret"`
}

func (c *CRVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	if len(c.PublicInputs) != 2 {
		panic("invalid public inputs, should contain 2 BN254 elements")
	}
	if len(c.OriginalPublicInputs) == 0 || len(c.OriginalPublicInputs)%64 != 0 {
		panic("invalid original public inputs, expected a non-empty multiple of 64 LE bits")
	}

	keccak, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}

	// Pack LE bits (grouped as Goldilocks 64-bit limbs) into big-endian bytes.
	limbCount := len(c.OriginalPublicInputs) / 64
	allBytes := make([]uints.U8, 0, limbCount*8)
	for i := 0; i < limbCount; i++ {
		// 64 LE bits for field element i, pack into 8 big-endian bytes
		for b := 0; b < 8; b++ {
			// big-endian byte b corresponds to bits at offset (7-b)*8
			bitBase := i*64 + (7-b)*8
			byteVal := frontend.Variable(0)
			for k := 7; k >= 0; k-- {
				byteVal = api.Mul(byteVal, 2)
				api.AssertIsBoolean(c.OriginalPublicInputs[bitBase+k].Limb)
				byteVal = api.Add(byteVal, c.OriginalPublicInputs[bitBase+k].Limb)
			}
			allBytes = append(allBytes, uints.U8{Val: byteVal})
		}
	}

	keccak.Write(allBytes)
	hash := keccak.Sum() // 32 U8 bytes

	// Accumulate hi (bytes 0..15) and lo (bytes 16..31) as BN254 field elements
	hi := frontend.Variable(0)
	for i := 0; i < 16; i++ {
		hi = api.Mul(hi, 256)
		hi = api.Add(hi, hash[i].Val)
	}
	lo := frontend.Variable(0)
	for i := 16; i < 32; i++ {
		lo = api.Mul(lo, 256)
		lo = api.Add(lo, hash[i].Val)
	}

	api.AssertIsEqual(c.PublicInputs[0], hi)
	api.AssertIsEqual(c.PublicInputs[1], lo)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

func initKeyStorePath(keystore_path string) {
	_, err := os.Stat(keystore_path)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(keystore_path, os.ModePerm)
		}
	}
}

func GenerateProof(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string, keystore_path string) (string, string) {
	initKeyStorePath(keystore_path)

	commonCircuitData := types.ReadCommonCircuitDataRaw(common_circuit_data)
	verifierOnlyCircuitDataRaw := types.ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataRaw)

	rawProofWithPis := types.ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

	// Pack LE bits (grouped as Goldilocks 64-bit limbs) back into big-endian bytes.
	if len(rawProofWithPis.PublicInputs) == 0 || len(rawProofWithPis.PublicInputs)%64 != 0 {
		panic("invalid original public inputs, expected a non-empty multiple of 64 LE bits")
	}
	limbCount := len(rawProofWithPis.PublicInputs) / 64
	buf := make([]byte, limbCount*8)
	for i := 0; i < limbCount; i++ {
		var val uint64
		for j := 0; j < 64; j++ {
			if rawProofWithPis.PublicInputs[i*64+j] == 1 {
				val |= 1 << uint(j)
			}
		}
		binary.BigEndian.PutUint64(buf[i*8:], val)
	}
	// Compute keccak256
	h := gosha3.NewLegacyKeccak256()
	h.Write(buf)
	hashBytes := h.Sum(nil)

	// Split into hi (128 bits) and lo (128 bits)
	hi := new(big.Int).SetBytes(hashBytes[:16])
	lo := new(big.Int).SetBytes(hashBytes[16:])
	hiVar := frontend.Variable(hi)
	loVar := frontend.Variable(lo)
	fmt.Println("keccak256 hi", hiVar)
	fmt.Println("keccak256 lo", loVar)

	circuit := CRVerifierCircuit{
		PublicInputs:            make([]frontend.Variable, 2),
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	assignment := CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{hiVar, loVar},
		Proof:                   circuit.Proof,
		OriginalPublicInputs:    circuit.OriginalPublicInputs,
		VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	// NewWitness() must be called before Compile() to avoid gnark panicking.
	// ref: https://github.com/Consensys/gnark/issues/1038
	t := time.Now()
	wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	fmt.Printf("[prove] NewWitness took %s\n", time.Since(t))

	t = time.Now()
	cs, pk, vk, err := Setup(&circuit, keystore_path)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[prove] Setup took %s\n", time.Since(t))

	t = time.Now()
	if err := debugUnsatisfiedConstraint(*cs, wit); err != nil {
		panic(err)
	}
	fmt.Printf("[prove] debugUnsatisfiedConstraint took %s\n", time.Since(t))

	var proof groth16.Proof
	var publicWitness witness.Witness
	var retries = 0

	for {
		t = time.Now()
		proof, err = groth16.Prove(*cs, pk, wit)
		if err != nil {
			panic(err)
		}
		fmt.Printf("[prove] groth16.Prove took %s\n", time.Since(t))

		publicWitness, err = wit.Public()
		if err != nil {
			panic(err)
		}

		t = time.Now()
		err = groth16.Verify(proof, vk, publicWitness)
		fmt.Printf("[prove] groth16.Verify took %s\n", time.Since(t))
		if err == nil {
			break
		}
		if retries > 5 {
			panic(err)
		}
		fmt.Println("generated bad proof, retrying...")
		retries += 1
	}

	bnProof := proof.(*groth16_bn254.Proof)
	bnWitness := publicWitness.Vector().(fr.Vector)

	original_proof_bytes, err := json.Marshal(&G16ProofWithPublicInputs{
		Proof:        bnProof,
		PublicInputs: publicWitness,
	})
	if err != nil {
		panic(err)
	}
	var g16VerifyingKey = G16VerifyingKey{
		VK: vk,
	}
	original_vk_bytes, err := json.Marshal(g16VerifyingKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("proofString", string(original_proof_bytes))
	fmt.Println("vkString", string(original_vk_bytes))
	_ = bnWitness

	// Add Solidity-ready EIP-197 proof/input arrays directly from BN254 coordinates.
	var proofMap map[string]interface{}
	if err := json.Unmarshal(original_proof_bytes, &proofMap); err != nil {
		panic(err)
	}
	proofMap["solidity_proof"] = [8]string{
		"0x" + fpHex(&bnProof.Ar.X),
		"0x" + fpHex(&bnProof.Ar.Y),
		"0x" + fpHex(&bnProof.Bs.X.A1),
		"0x" + fpHex(&bnProof.Bs.X.A0),
		"0x" + fpHex(&bnProof.Bs.Y.A1),
		"0x" + fpHex(&bnProof.Bs.Y.A0),
		"0x" + fpHex(&bnProof.Krs.X),
		"0x" + fpHex(&bnProof.Krs.Y),
	}
	proofMap["solidity_public_inputs"] = [2]string{
		fmt.Sprintf("0x%064x", hi),
		fmt.Sprintf("0x%064x", lo),
	}
	augmentedProofBytes, err := json.Marshal(proofMap)
	if err != nil {
		panic(err)
	}
	return string(augmentedProofBytes), string(original_vk_bytes)

}

func debugUnsatisfiedConstraint(ccs constraint.ConstraintSystem, wit witness.Witness) error {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger().Level(zerolog.DebugLevel)
	if err := ccs.IsSolved(wit, csolver.WithLogger(logger)); err != nil {
		fmt.Printf("IsSolved failed: %v\n", err)
		cid := -1
		switch e := err.(type) {
		case *csbn254.UnsatisfiedConstraintError:
			cid = e.CID
		case *csbls12381.UnsatisfiedConstraintError:
			cid = e.CID
		}
		if cid >= 0 {
			if r1cs, ok := ccs.(constraint.R1CS); ok {
				it := r1cs.GetR1CIterator()
				idx := 0
				for {
					r1c := it.Next()
					if r1c == nil {
						break
					}
					if idx == cid {
						fmt.Printf("Unsatisfied constraint #%d: %s\n", cid, r1c.String(r1cs))
						break
					}
					idx++
				}
			}
		}
		return err
	}
	return nil
}

func VerifyProof(proofString string, vkString string) string {
	g16ProofWithPublicInputs := NewG16ProofWithPublicInputs()
	if err := json.Unmarshal([]byte(proofString), g16ProofWithPublicInputs); err != nil {
		fmt.Println(err)
		return "false"
	}

	g16VerifyingKey := NewG16VerifyingKey()
	if err := json.Unmarshal([]byte(vkString), g16VerifyingKey); err != nil {
		fmt.Println(err)
		return "false"
	}

	if err := groth16.Verify(g16ProofWithPublicInputs.Proof, g16VerifyingKey.VK, g16ProofWithPublicInputs.PublicInputs); err != nil {
		fmt.Println(err)
		return "false"
	}
	return "true"
}

func Setup(circuit *CRVerifierCircuit, keystore_path string) (*constraint.ConstraintSystem, *groth16_bn254.ProvingKey, *groth16_bn254.VerifyingKey, error) {
	prepCircuitsMu.Lock()
	if c, ok := prepCircuits[keystore_path]; ok && c.CCS != nil && c.PKey != nil && c.VKey != nil {
		defer prepCircuitsMu.Unlock()
		return c.CCS, c.PKey, c.VKey, nil
	}
	prepCircuitsMu.Unlock()
	if CheckKeysExist(keystore_path) {
		fmt.Printf("[setup] loading existing groth16 setup from %s\n", keystore_path)
		t := time.Now()
		ccs, err := ReadCircuit(ecc.BN254, filepath.Join(keystore_path, CIRCUIT_PATH))
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] ReadCircuit took %s\n", time.Since(t))

		t = time.Now()
		vk, err := ReadVerifyingKey(ecc.BN254, filepath.Join(keystore_path, VK_PATH))
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] ReadVerifyingKey took %s\n", time.Since(t))

		t = time.Now()
		pk, err := ReadProvingKey(ecc.BN254, filepath.Join(keystore_path, PK_PATH))
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] ReadProvingKey took %s\n", time.Since(t))

		prepCircuitsMu.Lock()
		defer prepCircuitsMu.Unlock()
		if c, ok := prepCircuits[keystore_path]; ok && c.CCS != nil && c.PKey != nil && c.VKey != nil {
			return c.CCS, c.PKey, c.VKey, nil
		}
		prepCircuits[keystore_path] = &PreparedCircuit{
			CCS:  &ccs,
			PKey: pk.(*groth16_bn254.ProvingKey),
			VKey: vk.(*groth16_bn254.VerifyingKey),
		}
	} else {
		fmt.Printf("[setup] no groth16 setup found under %s; compiling circuit and generating a new setup\n", keystore_path)
		t := time.Now()
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] constraints: %d, commitments: %d\n", ccs.GetNbConstraints(), len(ccs.GetCommitments().CommitmentIndexes()))
		fmt.Printf("[setup] Compile took %s, constraints: %d\n", time.Since(t), ccs.GetNbConstraints())

		t = time.Now()
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] groth16.Setup took %s\n", time.Since(t))

		t = time.Now()
		if err := WriteCircuit(ccs, filepath.Join(keystore_path, CIRCUIT_PATH)); err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] WriteCircuit took %s\n", time.Since(t))

		t = time.Now()
		if err := WriteVerifyingKey(vk, filepath.Join(keystore_path, VK_PATH)); err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] WriteVerifyingKey took %s\n", time.Since(t))

		t = time.Now()
		if err := WriteProvingKey(pk, filepath.Join(keystore_path, PK_PATH)); err != nil {
			return nil, nil, nil, err
		}
		fmt.Printf("[setup] WriteProvingKey took %s\n", time.Since(t))

		prepCircuitsMu.Lock()
		defer prepCircuitsMu.Unlock()
		if c, ok := prepCircuits[keystore_path]; ok && c.CCS != nil && c.PKey != nil && c.VKey != nil {
			return c.CCS, c.PKey, c.VKey, nil
		}
		prepCircuits[keystore_path] = &PreparedCircuit{
			CCS:  &ccs,
			PKey: pk.(*groth16_bn254.ProvingKey),
			VKey: vk.(*groth16_bn254.VerifyingKey),
		}
	}

	c := prepCircuits[keystore_path]
	return c.CCS, c.PKey, c.VKey, nil
}

type DigestBitsError struct {
	Status uint32
	Message string
}

func (e *DigestBitsError) Error() string { return e.Message }

type DigestBitsIdentity struct {
	Schema uint32 `json:"schema"`
	Mode string `json:"mode"`
	Artifact uint32 `json:"artifact"`
	NodeSource string `json:"node_source"`
	NativeSource string `json:"native_source"`
	Plonky2Source string `json:"plonky2_source"`
	WrapperSource string `json:"wrapper_source"`
	NormalizerFingerprint []uint64 `json:"normalizer_fingerprint"`
	NormalizerCommon string `json:"normalizer_common"`
	NormalizerVerifier string `json:"normalizer_verifier"`
	FinalCommonJSON string `json:"final_common_json"`
	FinalVerifierJSON string `json:"final_verifier_json"`
}

type DigestBitsCircuit struct {
	PublicInputs []frontend.Variable `gnark:",public"`
	OriginalPublicInputs []gl.Variable
	Proof variables.Proof
	Common types.CommonCircuitData `gnark:"-"`
	Verifier variables.VerifierOnlyCircuitData `gnark:"-"`
}

func constrainDigestBits(api frontend.API, public []frontend.Variable, bits []gl.Variable) error {
	if len(public) != 2 || len(bits) != 256 {
		return fmt.Errorf("DigestBits requires two public inputs and 256 bits")
	}
	for half := 0; half < 2; half++ {
		var acc frontend.Variable = 0
		for _, bit := range bits[half*128:(half+1)*128] {
			api.AssertIsBoolean(bit.Limb)
			acc = api.Add(api.Mul(acc, 2), bit.Limb)
		}
		api.AssertIsEqual(public[half], acc)
	}
	return nil
}

func (c *DigestBitsCircuit) Define(api frontend.API) error {
	if c.Common.NumPublicInputs != 256 { return fmt.Errorf("final common input count is not 256") }
	if err := constrainDigestBits(api, c.PublicInputs, c.OriginalPublicInputs); err != nil { return err }
	verifier.NewVerifierChip(api, c.Common).Verify(c.Proof, c.OriginalPublicInputs, c.Verifier)
	return nil
}

func digestBitsHalves(bits []uint64) ([2]*big.Int, error) {
	var result [2]*big.Int
	if len(bits) != 256 { return result, fmt.Errorf("expected exactly 256 digest bits") }
	for half := range result {
		result[half] = new(big.Int)
		for _, bit := range bits[half*128:(half+1)*128] {
			if bit > 1 { return result, fmt.Errorf("digest input is not Boolean") }
			result[half].Lsh(result[half], 1)
			if bit == 1 { result[half].SetBit(result[half], 0, 1) }
		}
	}
	return result, nil
}

// Check duplicates recursively before decoding into the native schema.
func decodeDigestJSON(data []byte, value interface{}) error {
	if !utf8.Valid(data) { return fmt.Errorf("invalid UTF-8") }
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var visit func() error
	visit = func() error {
		token, err := d.Token()
		if err != nil { return err }
		if token == nil { return fmt.Errorf("null is not canonical") }
		delim, ok := token.(json.Delim)
		if !ok { return nil }
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token(); if err != nil { return err }
				name, ok := key.(string); if !ok || seen[name] { return fmt.Errorf("duplicate or invalid JSON field") }
				seen[name] = true
				if err := visit(); err != nil { return err }
			}
		case '[':
			for d.More() { if err := visit(); err != nil { return err } }
		default: return fmt.Errorf("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := visit(); err != nil { return err }
	if _, err := d.Token(); err != io.EOF { return fmt.Errorf("trailing JSON content") }
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

func digestHex(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || s != strings.ToLower(s) || len(b) == 0 || (size >= 0 && len(b) != size) {
		return nil, fmt.Errorf("noncanonical hexadecimal encoding")
	}
	return b, nil
}

func readDigestIdentity(artifact uint32, data string) (*DigestBitsIdentity, string, *DigestBitsError) {
	var identity DigestBitsIdentity
	if err := decodeDigestJSON([]byte(data), &identity); err != nil { return nil, "", &DigestBitsError{1, err.Error()} }
	if identity.Schema != 1 || identity.Mode != "DigestBits" || artifact < 1 || artifact > 3 || identity.Artifact != artifact {
		return nil, "", &DigestBitsError{2, "DigestBits schema, mode or artifact mismatch"}
	}
	for _, source := range []string{identity.NodeSource, identity.NativeSource, identity.Plonky2Source, identity.WrapperSource} {
		size := 20
		if strings.HasPrefix(source, "local:") { source = strings.TrimPrefix(source, "local:"); size = 32 }
		if _, err := digestHex(source, size); err != nil { return nil, "", &DigestBitsError{1, "invalid source revision"} }
	}
	if len(identity.NormalizerFingerprint) != 4 { return nil, "", &DigestBitsError{1, "fingerprint requires four limbs"} }
	for _, limb := range identity.NormalizerFingerprint {
		if limb >= 0xffffffff00000001 { return nil, "", &DigestBitsError{1, "noncanonical fingerprint limb"} }
	}
	common, err := digestHex(identity.NormalizerCommon, -1)
	if err != nil { return nil, "", &DigestBitsError{1, err.Error()} }
	verifierBytes, err := digestHex(identity.NormalizerVerifier, -1)
	if err != nil { return nil, "", &DigestBitsError{1, err.Error()} }
	var rawCommon types.CommonCircuitDataRaw
	var rawVerifier types.VerifierOnlyCircuitDataRaw
	if err := decodeDigestJSON([]byte(identity.FinalCommonJSON), &rawCommon); err != nil { return nil, "", &DigestBitsError{1, err.Error()} }
	if err := decodeDigestJSON([]byte(identity.FinalVerifierJSON), &rawVerifier); err != nil { return nil, "", &DigestBitsError{1, err.Error()} }
	if rawCommon.NumPublicInputs != 256 { return nil, "", &DigestBitsError{2, "final common input count must be 256"} }
	if rawCommon.FriParams.Hiding || rawCommon.Config.ZeroKnowledge { return nil, "", &DigestBitsError{2, "hiding is not supported"} }
	if rawCommon.FriParams.Config.CapHeight > 20 || len(rawVerifier.ConstantsSigmasCap) != 1<<rawCommon.FriParams.Config.CapHeight {
		return nil, "", &DigestBitsError{2, "final verifier cap shape mismatch"}
	}
	for _, hash := range append(append([]string{}, rawVerifier.ConstantsSigmasCap...), rawVerifier.CircuitDigest) {
		n, ok := new(big.Int).SetString(hash, 10)
		if !ok || n.Sign() < 0 || n.Cmp(ecc.BN254.ScalarField()) >= 0 || n.String() != hash { return nil, "", &DigestBitsError{1, "noncanonical final verifier hash"} }
	}
	h := sha256.New()
	h.Write([]byte("PsyBridge/DigestBits/1"))
	var word [8]byte
	binary.BigEndian.PutUint32(word[:4], identity.Schema); h.Write(word[:4])
	binary.BigEndian.PutUint32(word[:4], identity.Artifact); h.Write(word[:4])
	writeBytes := func(b []byte) { binary.BigEndian.PutUint64(word[:], uint64(len(b))); h.Write(word[:]); h.Write(b) }
	for _, s := range []string{identity.Mode, identity.NodeSource, identity.NativeSource, identity.Plonky2Source, identity.WrapperSource} { writeBytes([]byte(s)) }
	for _, limb := range identity.NormalizerFingerprint { binary.BigEndian.PutUint64(word[:], limb); h.Write(word[:]) }
	for _, b := range [][]byte{common, verifierBytes, []byte(identity.FinalCommonJSON), []byte(identity.FinalVerifierJSON)} { writeBytes(b) }
	return &identity, hex.EncodeToString(h.Sum(nil)), nil
}

func buildDigestCircuit(identity *DigestBitsIdentity) (*DigestBitsCircuit, error) {
	c := types.ReadCommonCircuitDataRaw(identity.FinalCommonJSON)
	proof, err := buildWrapperProof(c)
	if err != nil { return nil, err }
	return &DigestBitsCircuit{PublicInputs: make([]frontend.Variable, 2), OriginalPublicInputs: make([]gl.Variable, 256), Proof: proof, Common: c,
		Verifier: variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitDataRaw(identity.FinalVerifierJSON))}, nil
}

func buildWrapperProof(c types.CommonCircuitData) (variables.Proof, error) {
	p := c.FriParams
	if p.DegreeBits > 32 || p.Config.RateBits > 32 || p.Config.CapHeight > p.DegreeBits+p.Config.RateBits || p.Config.NumQueryRounds == 0 {
		return variables.Proof{}, fmt.Errorf("invalid final FRI shape")
	}
	remaining := p.DegreeBits
	for _, arity := range p.ReductionArityBits {
		if arity == 0 || arity > remaining || arity > 20 { return variables.Proof{}, fmt.Errorf("invalid FRI reduction shape") }
		remaining -= arity
	}
	if remaining > 20 { return variables.Proof{}, fmt.Errorf("final polynomial shape too large") }
	ext := func(n uint64) []gl.QuadraticExtensionVariable { return make([]gl.QuadraticExtensionVariable, n) }
	proof := variables.Proof{
		WiresCap: variables.NewFriMerkleCap(p.Config.CapHeight),
		PlonkZsPartialProductsCap: variables.NewFriMerkleCap(p.Config.CapHeight),
		QuotientPolysCap: variables.NewFriMerkleCap(p.Config.CapHeight),
		Openings: variables.OpeningSet{
			Constants: ext(c.NumConstants), PlonkSigmas: ext(c.Config.NumRoutedWires), Wires: ext(c.Config.NumWires),
			PlonkZs: ext(c.Config.NumChallenges), PlonkZsNext: ext(c.Config.NumChallenges),
			PartialProducts: ext(c.Config.NumChallenges*c.NumPartialProducts), QuotientPolys: ext(c.Config.NumChallenges*c.QuotientDegreeFactor),
		},
	}
	proof.OpeningProof.CommitPhaseMerkleCaps = make([]variables.FriMerkleCap, len(p.ReductionArityBits))
	for i := range proof.OpeningProof.CommitPhaseMerkleCaps { proof.OpeningProof.CommitPhaseMerkleCaps[i] = variables.NewFriMerkleCap(p.Config.CapHeight) }
	proof.OpeningProof.FinalPoly = variables.NewPolynomialCoeffs(1<<remaining)
	proof.OpeningProof.QueryRoundProofs = make([]variables.FriQueryRound, p.Config.NumQueryRounds)
	widths := []uint64{c.NumConstants+c.Config.NumRoutedWires, c.Config.NumWires, c.Config.NumChallenges*(1+c.NumPartialProducts), c.Config.NumChallenges*c.QuotientDegreeFactor}
	for i := range proof.OpeningProof.QueryRoundProofs {
		query := &proof.OpeningProof.QueryRoundProofs[i]
		height := p.DegreeBits+p.Config.RateBits-p.Config.CapHeight
		query.InitialTreesProof.EvalsProofs = make([]variables.FriEvalProof, 4)
		for j, width := range widths { query.InitialTreesProof.EvalsProofs[j] = variables.NewFriEvalProof(make([]gl.Variable, width), variables.NewFriMerkleProof(height)) }
		query.Steps = make([]variables.FriQueryStep, len(p.ReductionArityBits))
		for j, arity := range p.ReductionArityBits {
			if arity > height { return variables.Proof{}, fmt.Errorf("FRI reduction exceeds Merkle height") }
			height -= arity
			query.Steps[j] = variables.NewFriQueryStep(arity, height)
		}
	}
	return proof, nil
}

type digestBitsFile struct {
	Name string `json:"name"`
	SHA256 string `json:"sha256"`
}

type digestBitsManifest struct {
	Schema uint32 `json:"schema"`
	IdentityHash string `json:"identity_hash"`
	Files []digestBitsFile `json:"files"`
}

var digestBitsFileNames = []string{"circuit_groth16.bin", "identity.json", "pk_groth16.bin", "verifier.sol", "vk_groth16.bin"}

func readDigestArtifacts(dir, identityHash string, artifact uint32) (map[string][]byte, error) {
	files, err := readSetupFiles(dir, identityHash)
	if err != nil { return nil, err }
	_, storedHash, identityErr := readDigestIdentity(artifact, string(files["identity.json"]))
	if identityErr != nil || storedHash != identityHash { return nil, fmt.Errorf("stored identity mismatch") }
	return files, nil
}

func readSetupFiles(dir, identityHash string) (map[string][]byte, error) {
	read := func(name string) ([]byte, error) {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil { return nil, err }
		if !info.Mode().IsRegular() { return nil, fmt.Errorf("artifact %s is not a regular file", name) }
		return os.ReadFile(path)
	}
	data, err := read("manifest.json"); if err != nil { return nil, err }
	var manifest digestBitsManifest
	if err := decodeDigestJSON(data, &manifest); err != nil { return nil, err }
	if manifest.Schema != 1 || manifest.IdentityHash != identityHash || len(manifest.Files) != len(digestBitsFileNames) { return nil, fmt.Errorf("artifact identity or manifest mismatch") }
	files := make(map[string][]byte, len(manifest.Files))
	for i, entry := range manifest.Files {
		if entry.Name != digestBitsFileNames[i] { return nil, fmt.Errorf("manifest file set/order mismatch") }
		data, err := read(entry.Name); if err != nil { return nil, err }
		hash := sha256.Sum256(data)
		if entry.SHA256 != hex.EncodeToString(hash[:]) { return nil, fmt.Errorf("artifact digest mismatch: %s", entry.Name) }
		files[entry.Name] = data
	}
	return files, nil
}

func writeDigestArtifact(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return err }
	if err = write(f); err == nil { err = f.Sync() }
	closeErr := f.Close()
	if err != nil { return err }
	return closeErr
}

func SetupDigestBits(artifact uint32, identityJSON, artifactDir string) error {
	identity, identityHash, failure := readDigestIdentity(artifact, identityJSON)
	if failure != nil { return failure }
	if _, err := os.Lstat(artifactDir); err == nil { return &DigestBitsError{4, "artifact directory already exists"} } else if !os.IsNotExist(err) { return &DigestBitsError{4, err.Error()} }
	circuit, err := buildDigestCircuit(identity)
	if err != nil { return &DigestBitsError{2, err.Error()} }
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil { return &DigestBitsError{5, err.Error()} }
	pk, vk, err := groth16.Setup(ccs)
	if err != nil { return &DigestBitsError{5, err.Error()} }
	return publishDigestArtifacts(artifact, identityHash, artifactDir, func(name string, w io.Writer) error {
		var err error
		switch name {
		case "circuit_groth16.bin": _, err = ccs.WriteTo(w)
		case "pk_groth16.bin": _, err = pk.WriteTo(w)
		case "vk_groth16.bin": _, err = vk.WriteTo(w)
		case "identity.json": _, err = io.WriteString(w, identityJSON)
		case "verifier.sol": err = vk.ExportSolidity(w)
		}
		return err
	})
}

func publishDigestArtifacts(artifact uint32, identityHash, artifactDir string, write func(string, io.Writer) error) error {
	return publishDigestArtifactsWithParentSync(artifact, identityHash, artifactDir, write, syncDigestParent)
}

// The final durability operation is injectable without replacing publication or artifact validation.
func publishDigestArtifactsWithParentSync(artifact uint32, identityHash, artifactDir string, write func(string, io.Writer) error, syncParent func(string) error) (result error) {
	return publishSetupArtifacts(identityHash, artifactDir, write, syncParent, func(dir string) error {
		_, err := readDigestArtifacts(dir, identityHash, artifact)
		return err
	})
}

func publishSetupArtifacts(identityHash, artifactDir string, write func(string, io.Writer) error, syncParent func(string) error, validate func(string) error) (result error) {
	staging, err := os.MkdirTemp(filepath.Dir(artifactDir), "."+filepath.Base(artifactDir)+"-setup-")
	if err != nil { return &DigestBitsError{4, err.Error()} }
	published := false
	defer func() {
		if published { return }
		if err := os.RemoveAll(staging); err != nil {
			if result != nil { result = &DigestBitsError{4, fmt.Sprintf("%v; temporary artifact cleanup failed: %v", result, err)} } else { result = &DigestBitsError{4, "temporary artifact cleanup failed: " + err.Error()} }
		}
	}()
	manifest := digestBitsManifest{Schema: 1, IdentityHash: identityHash}
	for _, name := range digestBitsFileNames {
		if err := writeDigestArtifact(filepath.Join(staging, name), func(w io.Writer) error { return write(name, w) }); err != nil { return &DigestBitsError{4, err.Error()} }
		data, err := os.ReadFile(filepath.Join(staging, name)); if err != nil { return &DigestBitsError{4, err.Error()} }
		hash := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, digestBitsFile{name, hex.EncodeToString(hash[:])})
	}
	if err := writeDigestArtifact(filepath.Join(staging, "manifest.json"), func(w io.Writer) error { return json.NewEncoder(w).Encode(manifest) }); err != nil { return &DigestBitsError{4, err.Error()} }
	if err := validate(staging); err != nil { return &DigestBitsError{4, err.Error()} }
	for _, path := range []string{staging, filepath.Dir(artifactDir)} {
		f, err := os.Open(path); if err != nil { return &DigestBitsError{4, err.Error()} }
		err = f.Sync(); closeErr := f.Close(); if err == nil { err = closeErr }
		if err != nil { return &DigestBitsError{4, err.Error()} }
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, artifactDir, unix.RENAME_NOREPLACE); err != nil { return &DigestBitsError{4, err.Error()} }
	published = true
	if err := syncParent(filepath.Dir(artifactDir)); err != nil { return &DigestBitsError{4, err.Error()} }
	return nil
}

func syncDigestParent(path string) error {
	parent, err := os.Open(path)
	if err != nil { return err }
	err = parent.Sync()
	closeErr := parent.Close()
	if err != nil { return err }
	return closeErr
}

func sameDigestShape(a, b reflect.Value) bool {
	if a.Type() != b.Type() { return false }
	switch a.Kind() {
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ { if !sameDigestShape(a.Field(i), b.Field(i)) { return false } }
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() { return false }
		for i := 0; i < a.Len(); i++ { if !sameDigestShape(a.Index(i), b.Index(i)) { return false } }
	}
	return true
}

func GenerateDigestBitsProof(artifact uint32, identityJSON, proofJSON, artifactDir string) (string, string, error) {
	identity, identityHash, failure := readDigestIdentity(artifact, identityJSON)
	if failure != nil { return "", "", failure }
	var raw types.ProofWithPublicInputsRaw
	if err := decodeDigestJSON([]byte(proofJSON), &raw); err != nil { return "", "", &DigestBitsError{1, err.Error()} }
	halves, err := digestBitsHalves(raw.PublicInputs)
	if err != nil { return "", "", &DigestBitsError{2, err.Error()} }
	if err := validateDigestProofValue(reflect.ValueOf(raw.Proof)); err != nil { return "", "", &DigestBitsError{3, err.Error()} }
	circuit, err := buildDigestCircuit(identity)
	if err != nil { return "", "", &DigestBitsError{2, err.Error()} }
	proof := variables.DeserializeProofWithPublicInputs(raw)
	if !sameDigestShape(reflect.ValueOf(circuit.Proof), reflect.ValueOf(proof.Proof)) { return "", "", &DigestBitsError{3, "final proof shape mismatch"} }
	files, err := readDigestArtifacts(artifactDir, identityHash, artifact)
	if err != nil { return "", "", &DigestBitsError{4, err.Error()} }
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	var compiled bytes.Buffer
	if _, err := ccs.WriteTo(&compiled); err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	if !bytes.Equal(compiled.Bytes(), files["circuit_groth16.bin"]) { return "", "", &DigestBitsError{4, "compiled circuit does not match pinned identity"} }
	pk, vk := groth16.NewProvingKey(ecc.BN254), groth16.NewVerifyingKey(ecc.BN254)
	for _, entry := range []struct { name string; reader io.ReaderFrom }{{"pk_groth16.bin", pk}, {"vk_groth16.bin", vk}} {
		reader := bytes.NewReader(files[entry.name])
		if _, err := entry.reader.ReadFrom(reader); err != nil || reader.Len() != 0 { return "", "", &DigestBitsError{4, "invalid or trailing key bytes"} }
	}
	var solidity bytes.Buffer
	if err := vk.ExportSolidity(&solidity); err != nil || !bytes.Equal(solidity.Bytes(), files["verifier.sol"]) { return "", "", &DigestBitsError{4, "Solidity verifier/key mismatch"} }
	circuit.Proof = proof.Proof
	circuit.OriginalPublicInputs = proof.PublicInputs
	circuit.PublicInputs = []frontend.Variable{halves[0], halves[1]}
	wit, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil { return "", "", &DigestBitsError{3, err.Error()} }
	if err := ccs.IsSolved(wit); err != nil { return "", "", &DigestBitsError{3, err.Error()} }
	g16, err := groth16.Prove(ccs, pk, wit)
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	public, err := wit.Public()
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	if err := groth16.Verify(g16, vk, public); err != nil { return "", "", &DigestBitsError{4, "proof/key compatibility check failed: " + err.Error()} }
	proofBytes, err := json.Marshal(&G16ProofWithPublicInputs{Proof: g16.(*groth16_bn254.Proof), PublicInputs: public})
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	vkBytes, err := json.Marshal(G16VerifyingKey{VK: vk.(*groth16_bn254.VerifyingKey)})
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	return string(proofBytes), string(vkBytes), nil
}

func validateDigestProofValue(value reflect.Value) error {
	switch value.Kind() {
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ { if err := validateDigestProofValue(value.Field(i)); err != nil { return err } }
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if value.Type() == reflect.TypeOf([][]uint64{}) && value.Index(i).Len() != 2 { return fmt.Errorf("extension must have two limbs") }
			if err := validateDigestProofValue(value.Index(i)); err != nil { return err }
		}
	case reflect.Uint64:
		if value.Uint() >= 0xffffffff00000001 { return fmt.Errorf("noncanonical proof field element") }
	case reflect.String:
		s := value.String()
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.Sign() < 0 || n.Cmp(ecc.BN254.ScalarField()) >= 0 || n.String() != s { return fmt.Errorf("noncanonical proof hash") }
	}
	return nil
}

type FinalizeIdentity struct {
	Schema uint32 `json:"schema"`
	ChainIndices []uint16 `json:"chain_indices"`
	FinalCommonJSON string `json:"final_common_json"`
	FinalVerifierJSON string `json:"final_verifier_json"`
}

func readFinalizeIdentity(data string) (*FinalizeIdentity, string, error) {
	var identity FinalizeIdentity
	if err := decodeDigestJSON([]byte(data), &identity); err != nil { return nil, "", err }
	if identity.Schema != 1 || len(identity.ChainIndices) < 1 || len(identity.ChainIndices) > 256 { return nil, "", fmt.Errorf("invalid finalize identity") }
	for i, index := range identity.ChainIndices {
		if index > 255 || (i > 0 && identity.ChainIndices[i-1] >= index) { return nil, "", fmt.Errorf("invalid finalize chain list") }
	}
	var common types.CommonCircuitDataRaw
	var verifierData types.VerifierOnlyCircuitDataRaw
	if err := decodeDigestJSON([]byte(identity.FinalCommonJSON), &common); err != nil { return nil, "", err }
	if err := decodeDigestJSON([]byte(identity.FinalVerifierJSON), &verifierData); err != nil { return nil, "", err }
	if common.NumPublicInputs != uint64((144+72*len(identity.ChainIndices))*8) || common.FriParams.Hiding || common.Config.ZeroKnowledge { return nil, "", fmt.Errorf("invalid finalize common shape") }
	if common.FriParams.Config.CapHeight > 20 || len(verifierData.ConstantsSigmasCap) != 1<<common.FriParams.Config.CapHeight { return nil, "", fmt.Errorf("invalid finalize verifier cap") }
	for _, value := range append(append([]string{}, verifierData.ConstantsSigmasCap...), verifierData.CircuitDigest) {
		n, ok := new(big.Int).SetString(value, 10)
		if !ok || n.Sign() < 0 || n.Cmp(ecc.BN254.ScalarField()) >= 0 || n.String() != value { return nil, "", fmt.Errorf("invalid finalize verifier hash") }
	}
	h := sha256.New()
	h.Write([]byte("PsyBridge/FinalizeSetup/1"))
	var word [8]byte
	binary.BigEndian.PutUint16(word[:2], uint16(len(identity.ChainIndices))); h.Write(word[:2])
	for _, index := range identity.ChainIndices { h.Write([]byte{byte(index)}) }
	for _, value := range []string{identity.FinalCommonJSON, identity.FinalVerifierJSON} {
		binary.BigEndian.PutUint64(word[:], uint64(len(value))); h.Write(word[:]); h.Write([]byte(value))
	}
	return &identity, hex.EncodeToString(h.Sum(nil)), nil
}

func finalizeChainListHash(identity *FinalizeIdentity) []byte {
	h := gosha3.NewLegacyKeccak256()
	h.Write([]byte("PsyBridge/FinalizeChainList/1"))
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(identity.ChainIndices))); h.Write(count[:])
	for _, index := range identity.ChainIndices { h.Write([]byte{byte(index)}) }
	return h.Sum(nil)
}

func buildFinalizeCircuit(identity *FinalizeIdentity) (*CRVerifierCircuit, error) {
	c := types.ReadCommonCircuitDataRaw(identity.FinalCommonJSON)
	proof, err := buildWrapperProof(c)
	if err != nil { return nil, err }
	return &CRVerifierCircuit{PublicInputs: make([]frontend.Variable, 2), OriginalPublicInputs: make([]gl.Variable, c.NumPublicInputs), Proof: proof,
		CommonCircuitData: c, VerifierOnlyCircuitData: variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitDataRaw(identity.FinalVerifierJSON))}, nil
}

func exportFinalizeSolidity(vk groth16.VerifyingKey, identity *FinalizeIdentity) ([]byte, error) {
	var buf bytes.Buffer
	if err := vk.ExportSolidity(&buf); err != nil { return nil, err }
	code := buf.String()
	end := strings.LastIndex(code, "}")
	if end < 0 { return nil, fmt.Errorf("generated verifier contract missing") }
	getter := fmt.Sprintf("\n    function endpointChainListHash() external pure returns (bytes32) { return 0x%x; }\n", finalizeChainListHash(identity))
	return []byte(code[:end] + getter + code[end:]), nil
}

func readFinalizeArtifacts(dir, expectedHash string) (*FinalizeIdentity, map[string][]byte, error) {
	files, err := readSetupFiles(dir, expectedHash)
	if err != nil { return nil, nil, err }
	identity, hash, err := readFinalizeIdentity(string(files["identity.json"]))
	if err != nil || hash != expectedHash { return nil, nil, fmt.Errorf("finalize setup identity mismatch") }
	vk := groth16.NewVerifyingKey(ecc.BN254)
	reader := bytes.NewReader(files["vk_groth16.bin"])
	if _, err := vk.ReadFrom(reader); err != nil || reader.Len() != 0 { return nil, nil, fmt.Errorf("invalid finalize verifying key") }
	code, err := exportFinalizeSolidity(vk, identity)
	if err != nil || !bytes.Equal(code, files["verifier.sol"]) { return nil, nil, fmt.Errorf("finalize verifier key/chain-list mismatch") }
	return identity, files, nil
}

func SetupFinalize(identityJSON, artifactDir string) error {
	identity, hash, err := readFinalizeIdentity(identityJSON)
	if err != nil { return &DigestBitsError{2, err.Error()} }
	if _, err := os.Lstat(artifactDir); !os.IsNotExist(err) { return &DigestBitsError{4, "finalize output must not exist"} }
	circuit, err := buildFinalizeCircuit(identity)
	if err != nil { return &DigestBitsError{2, err.Error()} }
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil { return &DigestBitsError{5, err.Error()} }
	pk, vk, err := groth16.Setup(ccs)
	if err != nil { return &DigestBitsError{5, err.Error()} }
	return publishSetupArtifacts(hash, artifactDir, func(name string, w io.Writer) error {
		var err error
		switch name {
		case "circuit_groth16.bin": _, err = ccs.WriteTo(w)
		case "pk_groth16.bin": _, err = pk.WriteTo(w)
		case "vk_groth16.bin": _, err = vk.WriteTo(w)
		case "identity.json": _, err = io.WriteString(w, identityJSON)
		case "verifier.sol":
			var code []byte
			code, err = exportFinalizeSolidity(vk, identity)
			if err == nil { _, err = w.Write(code) }
		}
		return err
	}, syncDigestParent, func(dir string) error { _, _, err := readFinalizeArtifacts(dir, hash); return err })
}

func ExportFinalizeVerifier(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil { return "", err }
	_, hash, err := readFinalizeIdentity(string(data))
	if err != nil { return "", err }
	_, files, err := readFinalizeArtifacts(dir, hash)
	if err != nil { return "", err }
	return string(files["verifier.sol"]), nil
}

func ReadFinalizeSetupIdentity(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil { return "", err }
	_, hash, err := readFinalizeIdentity(string(data))
	if err != nil { return "", err }
	_, files, err := readFinalizeArtifacts(dir, hash)
	if err != nil { return "", err }
	return string(files["identity.json"]), nil
}

func GenerateFinalizeProof(identityJSON, proofJSON, artifactDir string) (string, string, error) {
	identity, hash, err := readFinalizeIdentity(identityJSON)
	if err != nil { return "", "", &DigestBitsError{2, err.Error()} }
	_, files, err := readFinalizeArtifacts(artifactDir, hash)
	if err != nil { return "", "", &DigestBitsError{4, err.Error()} }
	circuit, err := buildFinalizeCircuit(identity)
	if err != nil { return "", "", &DigestBitsError{2, err.Error()} }
	var raw types.ProofWithPublicInputsRaw
	if err := decodeDigestJSON([]byte(proofJSON), &raw); err != nil { return "", "", &DigestBitsError{1, err.Error()} }
	if len(raw.PublicInputs) != len(circuit.OriginalPublicInputs) { return "", "", &DigestBitsError{3, "finalize proof width mismatch"} }
	if err := validateDigestProofValue(reflect.ValueOf(raw.Proof)); err != nil { return "", "", &DigestBitsError{3, err.Error()} }
	encoded := make([]byte, len(raw.PublicInputs)/8)
	for i := range len(raw.PublicInputs)/64 {
		var limb uint64
		for j := range 64 {
			bit := raw.PublicInputs[i*64+j]
			if bit > 1 { return "", "", &DigestBitsError{3, "nonboolean finalize proof input"} }
			limb |= bit << uint(j)
		}
		binary.BigEndian.PutUint64(encoded[i*8:], limb)
	}
	h := gosha3.NewLegacyKeccak256(); h.Write(encoded); digest := h.Sum(nil)
	proof := variables.DeserializeProofWithPublicInputs(raw)
	if !sameDigestShape(reflect.ValueOf(circuit.Proof), reflect.ValueOf(proof.Proof)) { return "", "", &DigestBitsError{3, "finalize proof shape mismatch"} }
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	var compiled bytes.Buffer
	if _, err := ccs.WriteTo(&compiled); err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	if !bytes.Equal(compiled.Bytes(), files["circuit_groth16.bin"]) { return "", "", &DigestBitsError{4, "finalize circuit identity mismatch"} }
	pk, vk := groth16.NewProvingKey(ecc.BN254), groth16.NewVerifyingKey(ecc.BN254)
	for _, entry := range []struct { name string; reader io.ReaderFrom }{{"pk_groth16.bin", pk}, {"vk_groth16.bin", vk}} {
		reader := bytes.NewReader(files[entry.name])
		if _, err := entry.reader.ReadFrom(reader); err != nil || reader.Len() != 0 { return "", "", &DigestBitsError{4, "invalid finalize key bytes"} }
	}
	circuit.Proof, circuit.OriginalPublicInputs = proof.Proof, proof.PublicInputs
	circuit.PublicInputs = []frontend.Variable{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
	wit, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil { return "", "", &DigestBitsError{3, err.Error()} }
	if err := ccs.IsSolved(wit); err != nil { return "", "", &DigestBitsError{3, err.Error()} }
	g16, err := groth16.Prove(ccs, pk, wit)
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	public, err := wit.Public()
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	if err := groth16.Verify(g16, vk, public); err != nil { return "", "", &DigestBitsError{4, err.Error()} }
	proofBytes, err := json.Marshal(&G16ProofWithPublicInputs{Proof: g16.(*groth16_bn254.Proof), PublicInputs: public})
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	vkBytes, err := json.Marshal(G16VerifyingKey{VK: vk.(*groth16_bn254.VerifyingKey)})
	if err != nil { return "", "", &DigestBitsError{5, err.Error()} }
	return string(proofBytes), string(vkBytes), nil
}
