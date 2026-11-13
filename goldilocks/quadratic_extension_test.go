package goldilocks

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/test"
)

func TestQuadraticExtensionMulMaxCanonical(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &TestQuadraticExtensionMulCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	operand := NewQuadraticExtensionVariable(NewVariable(max), NewVariable(max))
	assignment := TestQuadraticExtensionMulCircuit{
		Operand1: operand, Operand2: operand,
		ExpectedResult: NewQuadraticExtensionVariable(NewVariable(8), NewVariable(2)),
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	assignment.ExpectedResult[0] = NewVariable(9)
	witness, err = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err == nil {
		t.Fatal("accepted an incorrect extension product")
	}
}

type canonicalExtensionMulAddCircuit struct {
	A, B, C, Result QuadraticExtensionVariable
}

func (c *canonicalExtensionMulAddCircuit) Define(api frontend.API) error {
	chip := New(api)
	result := chip.MulAddExtensionCanonical(c.A, c.B, c.C)
	chip.AssertIsEqualExtension(result, c.Result)
	return nil
}

func TestCanonicalExtensionMulAddMax(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalExtensionMulAddCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	operand := NewQuadraticExtensionVariable(NewVariable(max), NewVariable(max))
	assignment := canonicalExtensionMulAddCircuit{
		A: operand, B: operand, C: operand,
		Result: NewQuadraticExtensionVariable(NewVariable(7), NewVariable(1)),
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	assignment.Result[0] = NewVariable(8)
	witness, err = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err == nil {
		t.Fatal("accepted an incorrect extension multiply-add")
	}
}

// Compare against the general reduction on boundary values and exercise the
// tightened quotient bounds through a Groth16 proof.
type canonicalExtensionProductComparison struct {
	A, B, C QuadraticExtensionVariable
}

func (c *canonicalExtensionProductComparison) Define(api frontend.API) error {
	chip := New(api)
	chip.AssertIsEqualExtension(chip.MulAddExtensionCanonical(c.A, c.B, c.C), chip.MulAddExtension(c.A, c.B, c.C))
	return nil
}

func TestCanonicalExtensionProductBounds(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalExtensionProductComparison{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	values := []*big.Int{big.NewInt(0), big.NewInt(1), max}
	var witness frontend.Circuit
	for _, a := range values {
		for _, b := range values {
			for _, c := range values {
				witness = &canonicalExtensionProductComparison{
					A: NewQuadraticExtensionVariable(NewVariable(a), NewVariable(a)),
					B: NewQuadraticExtensionVariable(NewVariable(b), NewVariable(b)),
					C: NewQuadraticExtensionVariable(NewVariable(c), NewVariable(c)),
				}
				w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := cs.IsSolved(w); err != nil {
					t.Fatalf("a=%s b=%s c=%s: %v", a, b, c, err)
				}
			}
		}
	}
	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	public, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
}

type reduceWithPowersComparisonCircuit struct {
	Terms  [3]QuadraticExtensionVariable
	Scalar QuadraticExtensionVariable
}

func (c *reduceWithPowersComparisonCircuit) Define(api frontend.API) error {
	chip := New(api)
	optimized := chip.ReduceWithPowers(c.Terms[:], c.Scalar)
	general := ZeroExtension()
	for i := len(c.Terms) - 1; i >= 0; i-- {
		general = chip.MulAddExtension(general, c.Scalar, c.Terms[i])
	}
	chip.AssertIsEqualExtension(optimized, general)
	return nil
}

func TestReduceWithPowersMatchesGeneral(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &reduceWithPowersComparisonCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	values := []frontend.Variable{0, 1, max}
	for _, value := range values {
		v := NewQuadraticExtensionVariable(NewVariable(value), NewVariable(value))
		assignment := reduceWithPowersComparisonCircuit{Terms: [3]QuadraticExtensionVariable{v, v, v}, Scalar: v}
		witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := ccs.IsSolved(witness); err != nil {
			t.Errorf("value %v: %v", value, err)
		}
	}
}

type TestQuadraticExtensionMulCircuit struct {
	Operand1       QuadraticExtensionVariable
	Operand2       QuadraticExtensionVariable
	ExpectedResult QuadraticExtensionVariable
}

func (c *TestQuadraticExtensionMulCircuit) Define(api frontend.API) error {
	glApi := New(api)
	actualRes := glApi.MulExtension(c.Operand1, c.Operand2)
	glApi.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	glApi.AssertIsEqual(actualRes[1], c.ExpectedResult[1])
	return nil
}

func TestQuadraticExtensionMul4(t *testing.T) {
	assert := test.NewAssert(t)
	operand1 := QuadraticExtensionVariable{
		NewVariable("4994088319481652598"),
		NewVariable("16489566008211790727"),
	}
	operand2 := QuadraticExtensionVariable{
		NewVariable("3797605683985595697"),
		NewVariable("13424401189265534004"),
	}
	expectedResult := QuadraticExtensionVariable{
		NewVariable("15052319864161058789"),
		NewVariable("16841416332519902625"),
	}
	circuit := TestQuadraticExtensionMulCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	witness := TestQuadraticExtensionMulCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// Test for quadratic extension division
type TestQuadraticExtensionDivCircuit struct {
	Operand1       QuadraticExtensionVariable
	Operand2       QuadraticExtensionVariable
	ExpectedResult QuadraticExtensionVariable
}

func (c *TestQuadraticExtensionDivCircuit) Define(api frontend.API) error {
	glAPI := New(api)
	actualRes, _ := glAPI.DivExtension(c.Operand1, c.Operand2)
	glAPI.AssertIsEqual(actualRes[0], c.ExpectedResult[0])
	glAPI.AssertIsEqual(actualRes[1], c.ExpectedResult[1])
	return nil
}

func TestQuadraticExtensionDiv(t *testing.T) {
	assert := test.NewAssert(t)
	operand1 := QuadraticExtensionVariable{
		NewVariable("4994088319481652598"),
		NewVariable("16489566008211790727"),
	}
	operand2 := QuadraticExtensionVariable{
		NewVariable("7166004739148609569"),
		NewVariable("14655965871663555016"),
	}
	expectedResult := QuadraticExtensionVariable{
		NewVariable("15052319864161058789"),
		NewVariable("16841416332519902625"),
	}
	circuit := TestQuadraticExtensionDivCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	witness := TestQuadraticExtensionDivCircuit{
		Operand1:       operand1,
		Operand2:       operand2,
		ExpectedResult: expectedResult,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
