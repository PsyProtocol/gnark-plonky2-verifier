package poseidon

import (
	"math/big"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/test"
)

type sBoxCircuit struct {
	In, Out frontend.Variable
}

func (c *sBoxCircuit) Define(api frontend.API) error {
	chip := NewGoldilocksChip(api)
	out := chip.sBoxMonomial(gl.NewVariable(c.In))
	api.AssertIsEqual(out.Limb, c.Out)
	return nil
}

func TestSBoxCanonicalBoundaries(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &sBoxCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	values := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(gl.MODULUS, big.NewInt(1)), new(big.Int).Sub(gl.MODULUS, big.NewInt(2))}
	for _, x := range values {
		out := new(big.Int).Exp(x, big.NewInt(7), gl.MODULUS)
		witness, err := frontend.NewWitness(&sBoxCircuit{In: x, Out: out}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(witness); err != nil {
			t.Errorf("input %s: %v", x, err)
		}
	}
}

type mdsBoundaryCircuit struct {
	In  [SPONGE_WIDTH]frontend.Variable
	Out [SPONGE_WIDTH]frontend.Variable
}

func (c *mdsBoundaryCircuit) Define(api frontend.API) error {
	var state GoldilocksState
	for i := range state {
		state[i] = gl.NewVariable(c.In[i])
	}
	out := NewGoldilocksChip(api).mdsLayer(state)
	for i := range out {
		api.AssertIsEqual(out[i].Limb, c.Out[i])
	}
	return nil
}

func TestMDSCanonicalUpperBoundary(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mdsBoundaryCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	var assignment mdsBoundaryCircuit
	for i := range assignment.In {
		assignment.In[i] = new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
		coefficientSum := int64(256)
		if i == 0 {
			coefficientSum += 8
		}
		assignment.Out[i] = new(big.Int).Sub(gl.MODULUS, big.NewInt(coefficientSum))
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

type TestPoseidonCircuit struct {
	In  [12]frontend.Variable
	Out [12]frontend.Variable
}

func (circuit *TestPoseidonCircuit) Define(api frontend.API) error {
	var input GoldilocksState
	for i := 0; i < 12; i++ {
		input[i] = gl.NewVariable(circuit.In[i])
	}

	poseidonChip := NewGoldilocksChip(api)
	output := poseidonChip.Poseidon(input)

	glApi := gl.New(api)

	for i := 0; i < 12; i++ {
		glApi.AssertIsEqual(output[i], gl.NewVariable(circuit.Out[i]))
	}

	return nil
}

func TestPoseidonWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [12]frontend.Variable, out [12]frontend.Variable) {
		circuit := TestPoseidonCircuit{In: in, Out: out}
		witness := TestPoseidonCircuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	inStr := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := []string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}
	var in [12]frontend.Variable
	var out [12]frontend.Variable
	copy(in[:], gl.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], gl.StrArrayToFrontendVariableArray(outStr))
	testCase(in, out)
}

func TestPoseidonProof(t *testing.T) {
	inStr := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
	outStr := []string{
		"4330397376401421145", "14124799381142128323", "8742572140681234676",
		"14345658006221440202", "15524073338516903644", "5091405722150716653",
		"15002163819607624508", "2047012902665707362", "16106391063450633726",
		"4680844749859802542", "15019775476387350140", "1698615465718385111",
	}
	var in [12]frontend.Variable
	var out [12]frontend.Variable
	copy(in[:], gl.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], gl.StrArrayToFrontendVariableArray(outStr))

	circuit := TestPoseidonCircuit{In: in, Out: out}
	assignment := TestPoseidonCircuit{In: in, Out: out}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
