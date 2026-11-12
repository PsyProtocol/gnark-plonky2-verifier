package goldilocks

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/frontend/cs/scs"
	"github.com/zilong-dai/gnark/profile"
	"github.com/zilong-dai/gnark/test"
)

func TestMain(m *testing.M) {
	// gnark's test engine implements Commit but not Rangechecker. Match the
	// R1CS bit-decomposition path used by this verifier during tests.
	if err := os.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "true"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type bitDecompositionRangeCheckCircuit struct {
	X, Square frontend.Variable
}

func (c *bitDecompositionRangeCheckCircuit) Define(api frontend.API) error {
	gl := New(api)
	if gl.rangeCheckerType != BIT_DECOMP_RANGE_CHECKER {
		return fmt.Errorf("expected bit decomposition range checker, got %v", gl.rangeCheckerType)
	}
	gl.RangeCheckWithMaxBits(NewVariable(c.X), 8)
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Square)
	return nil
}

func TestBitDecompositionRangeCheckRejectsOutOfRange(t *testing.T) {
	t.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "false")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &bitDecompositionRangeCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		x, square int
		valid     bool
	}{{255, 65025, true}, {256, 65536, false}} {
		witness, err := frontend.NewWitness(&bitDecompositionRangeCheckCircuit{X: tc.x, Square: tc.square}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = ccs.IsSolved(witness)
		if (err == nil) != tc.valid {
			t.Errorf("x=%d: valid=%v, solve error=%v", tc.x, tc.valid, err)
		}
	}
}

type canonicalAddCircuit struct {
	A, B, Sum frontend.Variable
}

func (c *canonicalAddCircuit) Define(api frontend.API) error {
	chip := New(api)
	result := chip.Add(NewVariable(c.A), NewVariable(c.B))
	api.AssertIsEqual(result.Limb, c.Sum)
	return nil
}

func TestCanonicalAddBoundaries(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalAddCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	values := []*big.Int{big.NewInt(0), big.NewInt(1), max}
	for _, a := range values {
		for _, b := range values {
			sum := new(big.Int).Add(a, b)
			sum.Mod(sum, MODULUS)
			witness, err := frontend.NewWitness(&canonicalAddCircuit{A: a, B: b, Sum: sum}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := ccs.IsSolved(witness); err != nil {
				t.Errorf("%s + %s: %v", a, b, err)
			}
		}
	}
	witness, err := frontend.NewWitness(&canonicalAddCircuit{A: max, B: 1, Sum: 1}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(witness); err == nil {
		t.Fatal("accepted an incorrect modular sum")
	}
}

type TestGoldilocksRangeCheckCircuit struct {
	X frontend.Variable
}

func (c *TestGoldilocksRangeCheckCircuit) Define(api frontend.API) error {
	glApi := New(api)
	glApi.RangeCheck(NewVariable(c.X))
	return nil
}

func TestGoldilocksRangeCheckR1CSBoundaries(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &TestGoldilocksRangeCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		x     *big.Int
		valid bool
	}{
		{big.NewInt(0), true},
		{new(big.Int).Sub(MODULUS, big.NewInt(1)), true},
		{new(big.Int).Set(MODULUS), false},
		{new(big.Int).Add(MODULUS, big.NewInt(1)), false},
		{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)), false},
		{new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)), false},
	}
	for _, tc := range cases {
		witness, err := frontend.NewWitness(&TestGoldilocksRangeCheckCircuit{X: tc.x}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = ccs.IsSolved(witness)
		if (err == nil) != tc.valid {
			t.Errorf("x=%s: valid=%v, solve error=%v", tc.x, tc.valid, err)
		}
	}
}
func TestGoldilocksRangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestGoldilocksRangeCheckCircuit

	witness.X = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = 0
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = MODULUS
	assert.ProverFailed(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	one := big.NewInt(1)
	maxValidVal := new(big.Int).Sub(MODULUS, one)
	witness.X = maxValidVal
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type TestGoldilocksRangeCheckBenchmarkCircuit struct {
	X []frontend.Variable
}

func (c *TestGoldilocksRangeCheckBenchmarkCircuit) Define(api frontend.API) error {
	glApi := New(api)
	for _, x := range c.X {
		glApi.RangeCheck(NewVariable(x))
		glApi.Reduce(NewVariable(x))

	}
	return nil
}

func BenchmarkGoldilocksRangeCheck(b *testing.B) {
	var sizes = []int{5, 10, 15}
	for i := 0; i < len(sizes); i++ {
		var circuit, witness TestGoldilocksRangeCheckBenchmarkCircuit
		circuit.X = make([]frontend.Variable, 2<<sizes[i])
		witness.X = make([]frontend.Variable, 2<<sizes[i])
		for j := 0; j < len(circuit.X); j++ {
			witness.X[j] = 1
		}
		p := profile.Start()
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
		if err != nil {
			fmt.Println("error in building circuit", err)
			os.Exit(1)
		}
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}
}

type TestGoldilocksMulAddCircuit struct {
	X, Y, Z        frontend.Variable
	ExpectedResult frontend.Variable
}

func (c *TestGoldilocksMulAddCircuit) Define(api frontend.API) error {
	glApi := New(api)
	calculateValue := glApi.MulAdd(NewVariable(c.X), NewVariable(c.Y), NewVariable(c.Z))
	api.AssertIsEqual(calculateValue.Limb, c.ExpectedResult)
	return nil
}

func TestGoldilocksMulAdd(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestGoldilocksMulAddCircuit

	witness.X = 1
	witness.Y = 2
	witness.Z = 3
	witness.ExpectedResult = 5
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	bigOperand := new(big.Int).SetUint64(9223372036854775808)
	expectedValue, _ := new(big.Int).SetString("18446744068340842500", 10)

	witness.X = bigOperand
	witness.Y = bigOperand
	witness.Z = 3
	witness.ExpectedResult = expectedValue
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
