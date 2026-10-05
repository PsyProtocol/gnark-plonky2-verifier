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

type TestGoldilocksRangeCheckCircuit struct {
	X frontend.Variable
}

func (c *TestGoldilocksRangeCheckCircuit) Define(api frontend.API) error {
	glApi := New(api)
	glApi.RangeCheck(NewVariable(c.X))
	return nil
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

type TestGoldilocksNativeRangeCheckCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *TestGoldilocksNativeRangeCheckCircuit) Define(api frontend.API) error {
	glApi := New(api)
	if glApi.rangeCheckerType != NATIVE_RANGE_CHECKER {
		return fmt.Errorf("expected native range checker, got %v", glApi.rangeCheckerType)
	}
	api.AssertIsEqual(c.X, c.Y)
	glApi.RangeCheckWithMaxBits(NewVariable(c.X), 32)
	return nil
}

func TestGoldilocksNativeRangeCheck(t *testing.T) {
	t.Setenv("USE_BIT_DECOMPOSITION_RANGE_CHECK", "false")

	var circuit TestGoldilocksNativeRangeCheckCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	validAssignment := TestGoldilocksNativeRangeCheckCircuit{X: uint64(1<<32 - 1), Y: uint64(1<<32 - 1)}
	validWitness, err := frontend.NewWitness(&validAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(validWitness); err != nil {
		t.Fatalf("maximum 32-bit value rejected: %v", err)
	}

	invalidAssignment := TestGoldilocksNativeRangeCheckCircuit{X: uint64(1 << 32), Y: uint64(1 << 32)}
	invalidWitness, err := frontend.NewWitness(&invalidAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(invalidWitness); err == nil {
		t.Fatal("out-of-range 32-bit value accepted")
	}
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
