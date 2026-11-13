package goldilocks

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type algebraProductCircuit struct {
	A, B    [D][D]frontend.Variable
	Compare bool `gnark:"-"`
}

func (c *algebraProductCircuit) Define(api frontend.API) error {
	chip := New(api)
	var a, b QuadraticExtensionAlgebraVariable
	for i := range a {
		for j := range a[i] {
			a[i][j] = NewVariable(c.A[i][j])
			b[i][j] = NewVariable(c.B[i][j])
		}
	}
	result := chip.MulExtensionAlgebra(a, b)
	if c.Compare {
		old := chip.legacyMulExtensionAlgebra(a, b)
		for i := range result {
			for j := range result[i] {
				api.AssertIsEqual(result[i][j].Limb, old[i][j].Limb)
			}
		}
	} else {
		for i := range result {
			for j := range result[i] {
				api.AssertIsEqual(result[i][j].Limb, 0)
			}
		}
	}
	return nil
}

func zeroAlgebraAssignment(compare bool) algebraProductCircuit {
	var a algebraProductCircuit
	a.Compare = compare
	for i := range a.A {
		for j := range a.A[i] {
			a.A[i][j], a.B[i][j] = 0, 0
		}
	}
	return a
}

func TestAlgebraProductMatchesLegacy(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &algebraProductCircuit{Compare: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	rng := rand.New(rand.NewSource(111))
	for sample := 0; sample < 30; sample++ {
		a := zeroAlgebraAssignment(true)
		for i := range a.A {
			for j := range a.A[i] {
				switch sample {
				case 0:
					a.A[i][j], a.B[i][j] = 0, 0
				case 1:
					a.A[i][j], a.B[i][j] = new(big.Int).Sub(MODULUS, big.NewInt(1)), new(big.Int).Sub(MODULUS, big.NewInt(1))
				default:
					a.A[i][j] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), MODULUS)
					a.B[i][j] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), MODULUS)
				}
			}
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(w); err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
	}
}

func TestAlgebraProductRejectsNoncanonicalInputs(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &algebraProductCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for invalid := -1; invalid < 8; invalid++ {
		a := zeroAlgebraAssignment(false)
		if invalid >= 0 {
			if invalid < 4 {
				a.A[invalid/2][invalid%2] = MODULUS
			} else {
				i := invalid - 4
				a.B[i/2][i%2] = MODULUS
			}
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w)
		if (err == nil) != (invalid == -1) {
			t.Fatalf("input %d: %v", invalid, err)
		}
	}
}

func TestAlgebraProductGroth16(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &algebraProductCircuit{Compare: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	a := zeroAlgebraAssignment(true)
	for i := range a.A {
		for j := range a.A[i] {
			a.A[i][j] = i + j + 1
			a.B[i][j] = i + 2*j + 3
		}
	}
	w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
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
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
}

func TestAlgebraProductBounds(t *testing.T) {
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	bound := new(big.Int).Mul(max, max)
	bound.Mul(bound, big.NewInt(64))
	if new(big.Int).Div(new(big.Int).Set(bound), MODULUS).BitLen() > 80 || bound.Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("extension algebra product exceeds its bounds")
	}
	if new(big.Int).Lsh(new(big.Int).Set(MODULUS), 80).Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("80-bit quotient may wrap the host field")
	}
}
