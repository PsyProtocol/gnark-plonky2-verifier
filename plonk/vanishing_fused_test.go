package plonk

import (
	"math/big"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/plonk/gates"
	"github.com/cf/gnark-plonky2-verifier/poseidon"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type vanishingComparisonCircuit struct {
	Beta, Alpha, Gamma frontend.Variable
	Sigmas             [3][2]frontend.Variable
	Wires              [2][2]frontend.Variable
	Z, ZNext           [2]frontend.Variable
}

func TestFusedScalarMulAddBounds(t *testing.T) {
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	bound := new(big.Int).Mul(max, max)
	bound.Add(bound, max)
	quotient := new(big.Int).Div(new(big.Int).Set(bound), gl.MODULUS)
	if quotient.Cmp(gl.MODULUS) >= 0 || bound.Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("fused scalar multiply-add exceeds its quotient or host-field bound")
	}
}

func (c *vanishingComparisonCircuit) inputs() (variables.ProofChallenges, variables.OpeningSet) {
	qe := func(v [2]frontend.Variable) gl.QuadraticExtensionVariable {
		return gl.NewQuadraticExtensionVariable(gl.NewVariable(v[0]), gl.NewVariable(v[1]))
	}
	challenges := variables.ProofChallenges{PlonkBetas: []gl.Variable{gl.NewVariable(c.Beta)}, PlonkAlphas: []gl.Variable{gl.NewVariable(c.Alpha)}, PlonkGammas: []gl.Variable{gl.NewVariable(c.Gamma)}, PlonkZeta: qe([2]frontend.Variable{3, 1})}
	openings := variables.OpeningSet{PlonkZs: []gl.QuadraticExtensionVariable{qe(c.Z)}, PlonkZsNext: []gl.QuadraticExtensionVariable{qe(c.ZNext)}}
	for _, v := range c.Sigmas {
		openings.PlonkSigmas = append(openings.PlonkSigmas, qe(v))
	}
	for _, v := range c.Wires {
		openings.Wires = append(openings.Wires, qe(v))
	}
	return challenges, openings
}

func (c *vanishingComparisonCircuit) Define(api frontend.API) error {
	common := types.CommonCircuitData{Config: types.CircuitConfig{NumChallenges: 1, NumRoutedWires: 2}, DegreeBits: 1, QuotientDegreeFactor: 2, KIs: []uint64{1, 2}}
	chip := NewPlonkChip(api, common)
	challenges, openings := c.inputs()
	g := gl.New(api)
	g.RangeCheck(challenges.PlonkGammas[0])
	for _, v := range openings.Wires {
		g.RangeCheckQE(v)
	}
	for _, v := range openings.PlonkZs {
		g.RangeCheckQE(v)
	}
	for _, v := range openings.PlonkZsNext {
		g.RangeCheckQE(v)
	}
	vars := *gates.NewEvaluationVars(nil, nil, poseidon.GoldilocksHashOut{})
	power := gl.NewQuadraticExtensionVariable(gl.NewVariable(7), gl.NewVariable(1))
	current := chip.evalVanishingPoly(vars, challenges, openings, power)
	legacy := chip.legacyEvalVanishingPoly(vars, challenges, openings, power)
	for i := range current {
		g.AssertIsEqualExtension(current[i], legacy[i])
	}
	return nil
}

func randomVanishingAssignment(sample int, rng *rand.Rand) vanishingComparisonCircuit {
	value := func() frontend.Variable {
		if sample == 0 {
			return 0
		}
		if sample == 1 {
			return new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
		}
		return new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
	}
	a := vanishingComparisonCircuit{Beta: value(), Alpha: value(), Gamma: value()}
	for i := range a.Sigmas {
		for j := range a.Sigmas[i] {
			a.Sigmas[i][j] = value()
		}
	}
	for i := range a.Wires {
		for j := range a.Wires[i] {
			a.Wires[i][j] = value()
		}
	}
	for i := range a.Z {
		a.Z[i] = value()
		a.ZNext[i] = value()
	}
	return a
}

func TestVanishingFusedMatchesLegacy(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &vanishingComparisonCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	rng := rand.New(rand.NewSource(281))
	for i := 0; i < 30; i++ {
		a := randomVanishingAssignment(i, rng)
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(w); err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
	}
}

type vanishingRangeCircuit struct {
	Beta, Alpha frontend.Variable
	Sigmas      [3][2]frontend.Variable
}

func (c *vanishingRangeCircuit) Define(api frontend.API) error {
	challenges := variables.ProofChallenges{PlonkBetas: []gl.Variable{gl.NewVariable(c.Beta)}, PlonkAlphas: []gl.Variable{gl.NewVariable(c.Alpha)}}
	var openings variables.OpeningSet
	for _, v := range c.Sigmas {
		openings.PlonkSigmas = append(openings.PlonkSigmas, gl.NewQuadraticExtensionVariable(gl.NewVariable(v[0]), gl.NewVariable(v[1])))
	}
	(&PlonkChip{api: api}).rangeCheckVanishingInputs(challenges, openings)
	return nil
}
func TestVanishingInputsRejectNoncanonicalValues(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &vanishingRangeCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	for invalid := -1; invalid < 8; invalid++ {
		a := vanishingRangeCircuit{Beta: 0, Alpha: 0}
		for i := range a.Sigmas {
			for j := range a.Sigmas[i] {
				a.Sigmas[i][j] = 0
			}
		}
		switch {
		case invalid == 0:
			a.Beta = gl.MODULUS
		case invalid == 1:
			a.Alpha = gl.MODULUS
		case invalid >= 2:
			i := invalid - 2
			a.Sigmas[i/2][i%2] = gl.MODULUS
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w)
		if (err == nil) != (invalid == -1) {
			t.Fatalf("field %d: %v", invalid, err)
		}
	}
}
func TestVanishingFusedGroth16(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &vanishingComparisonCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	a := randomVanishingAssignment(2, rand.New(rand.NewSource(19)))
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
