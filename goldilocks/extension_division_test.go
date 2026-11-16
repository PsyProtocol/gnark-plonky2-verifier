package goldilocks

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/constraint/solver"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type addDivCircuit struct {
	A, B, Denominator, Acc QuadraticExtensionVariable
	Compare                bool `gnark:"-"`
}

func (c *addDivCircuit) Define(api frontend.API) error {
	g := New(api)
	for _, v := range []QuadraticExtensionVariable{c.A, c.B, c.Denominator, c.Acc} {
		g.RangeCheckQE(v)
	}
	out := g.AddDivExtensionCanonical(c.A, c.B, c.Denominator, c.Acc)
	if c.Compare {
		inverse, hasInverse := g.InverseExtension(c.Denominator)
		api.AssertIsEqual(hasInverse, 1)
		legacy := g.MulAddExtension(g.SubExtensionNoReduce(c.A, c.B), inverse, c.Acc)
		g.AssertIsEqualExtension(out, legacy)
	}
	return nil
}

func TestAddDivExtensionMatchesLegacy(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &addDivCircuit{Compare: true})
	if err != nil {
		t.Fatal(err)
	}
	max := new(big.Int).Sub(MODULUS, big.NewInt(1))
	rng := rand.New(rand.NewSource(89))
	var assignment addDivCircuit
	for k := 0; k < 24; k++ {
		for _, v := range []*QuadraticExtensionVariable{&assignment.A, &assignment.B, &assignment.Denominator, &assignment.Acc} {
			for i := range v {
				x := new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), MODULUS)
				if k == 0 {
					x.Set(max)
				}
				if k == 1 {
					x.SetUint64(0)
				}
				v[i] = NewVariable(x)
			}
		}
		if k == 1 {
			assignment.Denominator = OneExtension()
		}
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("case %d: %v", k, err)
		}
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
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

func TestAddDivExtensionRejectsForgedHints(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &addDivCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                   string
		numerator, denominator QuadraticExtensionVariable
		forged                 *big.Int
	}{
		{"zero denominator", ZeroExtension(), ZeroExtension(), big.NewInt(0)},
		{"wrong quotient", OneExtension(), OneExtension(), big.NewInt(0)},
		{"noncanonical quotient", ZeroExtension(), OneExtension(), MODULUS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assignment := addDivCircuit{A: tc.numerator, B: ZeroExtension(), Denominator: tc.denominator, Acc: ZeroExtension()}
			w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			fake := func(_ *big.Int, _ []*big.Int, out []*big.Int) error {
				out[0].Set(tc.forged)
				out[1].SetUint64(0)
				return nil
			}
			if err := cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(addDivExtensionHint), fake)); err == nil {
				t.Fatal("accepted forged hint")
			}
		})
	}
}
