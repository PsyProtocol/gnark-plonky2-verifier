package worker

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/GopherJ/doge-covenant/serialize"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/zilong-dai/gnark/backend/groth16"
	bn254 "github.com/zilong-dai/gnark/backend/groth16/bn254"
	"github.com/zilong-dai/gnark/backend/witness"
)

var CIRCUIT_PATH string = "circuit_groth16.bin"
var VK_PATH string = "vk_groth16.bin"
var PK_PATH string = "pk_groth16.bin"
var PROOF_PATH string = "proof_groth16.bin"
var WITNESS_PATH string = "witness_groth16.bin"

type G16ProofWithPublicInputs struct {
	Proof        groth16.Proof
	PublicInputs witness.Witness
}

func Chunk(str string, chunk int) []string {
	if len(str) < chunk*64 {
		panic("proof field element string too short")
	}
	res := make([]string, chunk)

	// chunkSize := len(str) / chunk

	for i := 0; i < chunk; i++ {
		res[i] = str[i*64 : (i+1)*64]
	}

	return res
}

func (p G16ProofWithPublicInputs) MarshalJSON() ([]byte, error) {

	proof := p.Proof.(*bn254.Proof)

	var buf [32 * 2]byte
	var writer bytes.Buffer

	for i := 0; i < len(proof.Commitments); i++ {
		buf = proof.Commitments[i].RawBytes()
		_, err := writer.Write(buf[:])
		if err != nil {
			return nil, err
		}
	}

	pi_a_arr := Chunk(hex.EncodeToString((&proof.Ar).Marshal()), 2)
	pi_b_arr := Chunk(hex.EncodeToString((&proof.Bs).Marshal()), 4)
	pi_c_arr := Chunk(hex.EncodeToString((&proof.Krs).Marshal()), 2)
	var buffer bytes.Buffer
	n, err := p.PublicInputs.WriteTo(&buffer)
	if err != nil {
		return nil, err
	}
	raw := buffer.Bytes()
	if int64(len(raw)) != n || len(raw) < 12 {
		return nil, fmt.Errorf("incomplete public witness")
	}
	publicCount := binary.BigEndian.Uint32(raw[0:4])
	secretCount := binary.BigEndian.Uint32(raw[4:8])
	vectorCount := binary.BigEndian.Uint32(raw[8:12])
	if publicCount != 2 && publicCount != 6 || secretCount != 0 || vectorCount != publicCount || len(raw) != 12+32*int(publicCount) {
		return nil, fmt.Errorf("public witness count must be 2 or 6")
	}
	words := make([]string, publicCount)
	for i := range words {
		words[i] = hex.EncodeToString(raw[12+32*i : 12+32*(i+1)])
	}

	proof_map := map[string]interface{}{
		"pi_a":          [2]string{pi_a_arr[0], pi_a_arr[1]},
		"pi_b":          [2][2]string{{pi_b_arr[1], pi_b_arr[0]}, {pi_b_arr[3], pi_b_arr[2]}},
		"pi_c":          [2]string{pi_c_arr[0], pi_c_arr[1]},
		"Commitments":   hex.EncodeToString(writer.Bytes()),
		"CommitmentPok": hex.EncodeToString((&proof.CommitmentPok).Marshal()),
		"public_inputs": words,
	}
	return json.Marshal(proof_map)
}


func NewG16ProofWithPublicInputs() *G16ProofWithPublicInputs {

	proof := groth16.NewProof(ecc.BN254)

	publicInputs, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	return &G16ProofWithPublicInputs{
		Proof:        proof,
		PublicInputs: publicInputs,
	}

}

func FromCityProof(cityProof serialize.CityGroth16ProofData) (*G16ProofWithPublicInputs, error) {
	g16ProofWithPublicInputs := NewG16ProofWithPublicInputs()
	proof := g16ProofWithPublicInputs.Proof.(*bn254.Proof)
	ar, err := DeSerializeG1MCL(cityProof.PiA)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize PiA: %w", err)
	}
	proof.Ar = *ar

	bs, err := DeSerializeG2MCL(cityProof.PiBA0, cityProof.PiBA1)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize PiB: %w", err)
	}
	proof.Bs = *bs

	krs, err := DeSerializeG1MCL(cityProof.PiC)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Krs: %w", err)
	}
	proof.Krs = *krs

	publicinputs_bytes, err := hex.DecodeString("000000020000000000000002" + reverseHexString(cityProof.PublicInput0) + reverseHexString(cityProof.PublicInput1))

	if err != nil {
		return nil, fmt.Errorf("failed to decode public inputs: %w", err)
	}

	reader := bytes.NewReader(publicinputs_bytes)

	if _, err = g16ProofWithPublicInputs.PublicInputs.ReadFrom(reader); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read public inputs: %w", err)
	}

	return g16ProofWithPublicInputs, nil

}

func FromCityVk(cityVk serialize.CityGroth16VerifierData) (*G16VerifyingKey, error) {
	g16VerifyingKey := NewG16VerifyingKey()
	vk := g16VerifyingKey.VK.(*bn254.VerifyingKey)
	alphag1, err := DeSerializeG1MCL(cityVk.AlphaG1)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize alpha: %w", err)
	}
	vk.G1.Alpha = *alphag1

	betag2, err := DeSerializeG2MCL(cityVk.BetaG2[:64], cityVk.BetaG2[64:])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize beta: %w", err)
	}
	vk.G2.Beta = *betag2

	gammag2, err := DeSerializeG2MCL(cityVk.GammaG2[:64], cityVk.GammaG2[64:])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize gamma: %w", err)
	}
	vk.G2.Gamma = *gammag2

	deltag2, err := DeSerializeG2MCL(cityVk.DeltaG2[:64], cityVk.DeltaG2[64:])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize delta: %w", err)
	}
	vk.G2.Delta = *deltag2

	for i, kstr := range cityVk.G1K {

		ki, err := DeSerializeG1MCL(kstr)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize k[%d]: %w", i, err)
		}

		vk.G1.K = append(vk.G1.K, *ki)
	}
	vk.PublicAndCommitmentCommitted = make([][]int, 0)

	// comkey_bytes, err := hex.DecodeString("120aeea7669f3e488b05b65d76862ee78d0737f3a6bdeb3f0c24b77747e8675565a89c2e6bf013cd4390b5b274ba634c0f5b115f62064164037c30948baace9ed5437b2772e1f78541601ab59c3318b15f50010f564df7a03d238267b3c08df2081a8c4f74a2ad1a63369edf890ce207b5a5c86cee6838c8178958b744c34743e60ead4adb2ba3c11490392bdb7ee0840fba81035d99404a7a2aa21910742163f15ef7e654f55b64b2b0750781319ce040801ffe2cf1c0bcda6a31723a0f46a11096c4dfaea70d4f9edc44873f97f574cb39c38599199796e0a45eb68c0d365171cccdb9e3a0e528e509abece517d034068f671d85c2ca287865ef9f74e442258624122dd2f92c83872661c7983df0ee2ab1185eef9bd933aac7ea3a620753cf0aadee61fa7afc6ceabff71d9659adfe1a1259c10e8e45e634b1fdeb49229cfd87f4d3d7b34f86258902d3ab96fc2826150d1e833f09c5d7e681384b26b3448becc7db8b935a121523a584f61fcb43d51c267488bf534607fbbcaf50c3cee175")
	comkey_bytes, err := hex.DecodeString("131dfc75ee3d8a58cc0a50f30e7cd51b195cb5dffd2d2bc481825c542e3973b6cde81ed5ca4fb26b28876676c240903612d39d793a9bf95ccc517df9f1bd38cbdc5a22ef202a9d2a335cc16d644ec7e12072ea89511a67809e71740ed648612817d563d8aac0453222c8e78f4217d2656048a1d9733b17daa0cef428026b210d5c90457575581c97be731b8b2a80dae4051bf75f355450d53eb536a6e6d5f7cd5b816a6e7bb597e03e109a2c7646922f95d5c382dba68db9b5dd50aa2350406d0919ab988fb65631cbefb564998306b77fdacd68c87dd9bdba348caa12601af2a97fa58ebe2bd64494c762fbd7b8a5ac0daef5018e2f78f4d11516a7ad9db1e63288db4ef9160e11adce5f5229689701b9854aa6bf35bb53e715d6753bd8d14d06307ff6ca3c41f1c0a3a65929f2da36dc56c1f0ec322fe2838180878465fb42df4ac888070bf7f943603dcfcb8edfc200c2b9a84c4d14ce22c869173564ce05b5129f4d2fa89773f4446eaed5b598ef5155cadbb24900e39bca32be93804db0")
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize commitment key: %w", err)
	}
	if _, err := vk.CommitmentKey.ReadFrom(bytes.NewReader(comkey_bytes)); err != nil {
		return nil, fmt.Errorf("failed to read commitment key: %w", err)
	}
	err = vk.Precompute()
	if err != nil {
		return nil, fmt.Errorf("failed to precompute: %w", err)
	}

	return g16VerifyingKey, nil
}

func (p *G16ProofWithPublicInputs) UnmarshalJSON(data []byte) error {
	proof := p.Proof.(*bn254.Proof)
	var ProofString struct {
		PiA           [2]string    `json:"pi_a"`
		PiB           [2][2]string `json:"pi_b"`
		PiC           [2]string    `json:"pi_c"`
		Commitments   string       `json:"Commitments"`
		CommitmentPok string       `json:"CommitmentPok"`
		PublicInputs  []string     `json:"public_inputs"`
	}

	err := json.Unmarshal(data, &ProofString)
	if err != nil {
		return err
	}

	pia_bytes, err := hex.DecodeString(ProofString.PiA[0] + ProofString.PiA[1])
	if err != nil {
		return err
	}
	err = proof.Ar.Unmarshal(pia_bytes)
	if err != nil {
		return err
	}

	pib_bytes, err := hex.DecodeString(ProofString.PiB[0][1] + ProofString.PiB[0][0] + ProofString.PiB[1][1] + ProofString.PiB[1][0])
	if err != nil {
		return err
	}
	err = proof.Bs.Unmarshal(pib_bytes)
	if err != nil {
		return err
	}

	pic_bytes, err := hex.DecodeString(ProofString.PiC[0] + ProofString.PiC[1])
	if err != nil {
		return err
	}
	err = proof.Krs.Unmarshal(pic_bytes)
	if err != nil {
		return err
	}

	com_bytes, err := hex.DecodeString(ProofString.Commitments)
	if err != nil {
		return err
	}
	commitmentCount := len(com_bytes) / 64
	proof.Commitments = make([]curve.G1Affine, commitmentCount)
	for i := 0; i < commitmentCount; i++ {
		err = proof.Commitments[i].Unmarshal(com_bytes[64*i : 64*(i+1)])
		if err != nil {
			return err
		}
	}

	compok_bytes, err := hex.DecodeString(ProofString.CommitmentPok)
	if err != nil {
		return err
	}
	err = proof.CommitmentPok.Unmarshal(compok_bytes)
	if err != nil {
		return err
	}

	if len(ProofString.PublicInputs) != 2 && len(ProofString.PublicInputs) != 6 {
		return fmt.Errorf("public input count must be 2 or 6")
	}
	var witnessHeader [12]byte
	count := uint32(len(ProofString.PublicInputs))
	binary.BigEndian.PutUint32(witnessHeader[0:4], count)
	binary.BigEndian.PutUint32(witnessHeader[8:12], count)
	publicinputs := make([]byte, 0, len(witnessHeader)+32*len(ProofString.PublicInputs))
	publicinputs = append(publicinputs, witnessHeader[:]...)
	for _, word := range ProofString.PublicInputs {
		decoded, err := hex.DecodeString(word)
		if err != nil || word != hex.EncodeToString(decoded) || len(decoded) != 32 {
			return fmt.Errorf("public input must be 64 lowercase hexadecimal digits")
		}
		publicinputs = append(publicinputs, decoded...)
	}

	reader := bytes.NewReader(publicinputs)
	read, err := p.PublicInputs.ReadFrom(reader)
	if err != nil || read != int64(len(publicinputs)) || reader.Len() != 0 {
		return fmt.Errorf("invalid public witness")
	}

	return nil
}

type G16VerifyingKey struct {
	VK groth16.VerifyingKey
}

func NewG16VerifyingKey() *G16VerifyingKey {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	return &G16VerifyingKey{
		VK: vk,
	}
}

// type VerifyingKey struct {
// 	// [α]₁, [Kvk]₁
// 	G1 struct {
// 		Alpha       curve.G1Affine
// 		Beta, Delta curve.G1Affine   // unused, here for compatibility purposes
// 		K           []curve.G1Affine // The indexes correspond to the public wires
// 	}

// 	// [β]₂, [δ]₂, [γ]₂,
// 	// -[δ]₂, -[γ]₂: see proof.Verify() for more details
// 	G2 struct {
// 		Beta, Delta, Gamma curve.G2Affine
// 		deltaNeg, gammaNeg curve.G2Affine // not serialized
// 	}

// 	// e(α, β)
// 	e curve.GT // not serialized

// 	CommitmentKey                pedersen.VerifyingKey
// 	PublicAndCommitmentCommitted [][]int // indexes of public/commitment committed variables
// }

// pub struct VerifyingKey<E: Pairing> {
//     pub alpha_g1: E::G1Affine,
//     pub beta_g2: E::G2Affine,
//     pub gamma_g2: E::G2Affine,
//     pub delta_g2: E::G2Affine,
//     pub gamma_abc_g1: Vec<E::G1Affine>,
// }

func (gvk G16VerifyingKey) MarshalJSON() ([]byte, error) {
	vk := gvk.VK.(*bn254.VerifyingKey)
	var buf [32 * 2]byte

	gamma_abc_g1_arr := make([][]string, len(vk.G1.K))
	for i := 0; i < len(vk.G1.K); i++ {
		gamma_abc_g1_arr[i] = make([]string, 2)
	}
	for i := 0; i < len(vk.G1.K); i++ {
		buf = vk.G1.K[i].RawBytes()
		gamma_abc_g1_arr[i][0] = hex.EncodeToString(buf[:])[0:64]
		gamma_abc_g1_arr[i][1] = hex.EncodeToString(buf[:])[64:128]
	}

	var comkey_writer bytes.Buffer

	vk.CommitmentKey.WriteRawTo(&comkey_writer)

	alpha_g1_arr := Chunk(hex.EncodeToString((&vk.G1.Alpha).Marshal()), 2)
	beta_g2_arr := Chunk(hex.EncodeToString((&vk.G2.Beta).Marshal()), 4)
	gamma_g2_arr := Chunk(hex.EncodeToString((&vk.G2.Gamma).Marshal()), 4)
	delta_g2_arr := Chunk(hex.EncodeToString((&vk.G2.Delta).Marshal()), 4)
	CommitmentKey := hex.EncodeToString(comkey_writer.Bytes())

	vk_map := map[string]interface{}{
		"alpha_g1":      [2]string{alpha_g1_arr[0], alpha_g1_arr[1]},
		"beta_g2":       [2][2]string{{beta_g2_arr[1], beta_g2_arr[0]}, {beta_g2_arr[3], beta_g2_arr[2]}},
		"gamma_g2":      [2][2]string{{gamma_g2_arr[1], gamma_g2_arr[0]}, {gamma_g2_arr[3], gamma_g2_arr[2]}},
		"delta_g2":      [2][2]string{{delta_g2_arr[1], delta_g2_arr[0]}, {delta_g2_arr[3], delta_g2_arr[2]}},
		"gamma_abc_g1":  gamma_abc_g1_arr,
		"CommitmentKey": CommitmentKey,
		// "CommitmentKeyG": hex.EncodeToString((&vk.CommitmentKey.g).Marshal()),
		// "CommitmentKeyGRoot": hex.EncodeToString((&vk.CommitmentKey.gRootSigmaNeg).Marshal()),
		"PublicAndCommitmentCommitted": vk.PublicAndCommitmentCommitted,
	}

	return json.Marshal(vk_map)
}

func (gvk *G16VerifyingKey) UnmarshalJSON(data []byte) error {
	vk := gvk.VK.(*bn254.VerifyingKey)
	var VerifyingKeyString struct {
		Alpha         [2]string    `json:"alpha_g1"`
		K             [][]string   `json:"gamma_abc_g1"`
		Beta          [2][2]string `json:"beta_g2"`
		Gamma         [2][2]string `json:"gamma_g2"`
		Delta         [2][2]string `json:"delta_g2"`
		CommitmentKey string       `json:"CommitmentKey"`
		// CommitmentKeyG string
		// CommitmentKeyGRoot string
		PublicAndCommitmentCommitted [][]int `json:"PublicAndCommitmentCommitted"`
	}

	err := json.Unmarshal(data, &VerifyingKeyString)
	if err != nil {
		return err
	}

	alpha_bytes, err := hex.DecodeString(VerifyingKeyString.Alpha[0] + VerifyingKeyString.Alpha[1])
	if err != nil {
		return err
	}
	err = vk.G1.Alpha.Unmarshal(alpha_bytes)
	if err != nil {
		return err
	}

	len := len(VerifyingKeyString.K)
	vk.G1.K = make([]curve.G1Affine, len)
	for i := 0; i < len; i++ {
		k_bytes, err := hex.DecodeString(VerifyingKeyString.K[i][0] + VerifyingKeyString.K[i][1])
		if err != nil {
			return err
		}
		err = vk.G1.K[i].Unmarshal(k_bytes)
		if err != nil {
			return err
		}
	}

	beta_bytes, err := hex.DecodeString(VerifyingKeyString.Beta[0][1] + VerifyingKeyString.Beta[0][0] + VerifyingKeyString.Beta[1][1] + VerifyingKeyString.Beta[1][0])
	if err != nil {
		return err
	}
	err = vk.G2.Beta.Unmarshal(beta_bytes)
	if err != nil {
		return err
	}

	gamma_bytes, err := hex.DecodeString(VerifyingKeyString.Gamma[0][1] + VerifyingKeyString.Gamma[0][0] + VerifyingKeyString.Gamma[1][1] + VerifyingKeyString.Gamma[1][0])
	if err != nil {
		return err
	}
	err = vk.G2.Gamma.Unmarshal(gamma_bytes)
	if err != nil {
		return err
	}

	delta_bytes, err := hex.DecodeString(VerifyingKeyString.Delta[0][1] + VerifyingKeyString.Delta[0][0] + VerifyingKeyString.Delta[1][1] + VerifyingKeyString.Delta[1][0])
	if err != nil {
		return err
	}
	err = vk.G2.Delta.Unmarshal(delta_bytes)
	if err != nil {
		return err
	}

	comkey_bytes, err := hex.DecodeString(VerifyingKeyString.CommitmentKey)
	if err != nil {
		return err
	}
	_, err = vk.CommitmentKey.ReadFrom(bytes.NewReader(comkey_bytes))
	if err != nil {
		return err
	}

	vk.PublicAndCommitmentCommitted = VerifyingKeyString.PublicAndCommitmentCommitted

	err = vk.Precompute()
	if err != nil {
		return err
	}

	return nil
}
