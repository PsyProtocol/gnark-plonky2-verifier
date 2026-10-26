package worker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/zilong-dai/gnark/backend/groth16"
	groth16_bn254 "github.com/zilong-dai/gnark/backend/groth16/bn254"
	"github.com/zilong-dai/gnark/backend/witness"
	"github.com/zilong-dai/gnark/constraint"
	csbls12381 "github.com/zilong-dai/gnark/constraint/bls12-381"
	csbn254 "github.com/zilong-dai/gnark/constraint/bn254"
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

	var proof groth16.Proof
	var publicWitness witness.Witness
	var retries = 0

	for {
		t = time.Now()
		proof, err = proveWithDiagnostics(*cs, pk, wit)
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

// Prove already solves and checks the constraints. Diagnose its returned error
// instead of solving the entire witness a second time before every proof.
func proveWithDiagnostics(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, wit witness.Witness) (groth16.Proof, error) {
	proof, err := groth16.Prove(ccs, pk, wit)
	if err != nil {
		fmt.Printf("groth16.Prove failed: %v\n", err)
		cid := -1
		var bn254Error *csbn254.UnsatisfiedConstraintError
		var bls12381Error *csbls12381.UnsatisfiedConstraintError
		switch {
		case errors.As(err, &bn254Error):
			cid = bn254Error.CID
		case errors.As(err, &bls12381Error):
			cid = bls12381Error.CID
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
		return nil, err
	}
	return proof, nil
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
