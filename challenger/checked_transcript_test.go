package challenger

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"

	"github.com/cf/gnark-plonky2-verifier/fri"
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type checkedTranscriptCircuit struct {
	Hash     frontend.Variable
	Openings [3][2]frontend.Variable
	Final    [2][2]frontend.Variable
	Pow      frontend.Variable
}

func (c *checkedTranscriptCircuit) Define(api frontend.API) error {
	checked, legacy := NewChip(api), NewChip(api)
	checked.ObserveBN254Hash(c.Hash)
	// Exercise the previous reduction path for the same constrained chunks.
	legacy.ObserveElements(legacy.poseidonBN254Chip.ToVec(c.Hash))
	var openings fri.Openings
	batch := fri.OpeningBatch{}
	for _, v := range c.Openings {
		batch.Values = append(batch.Values, gl.NewQuadraticExtensionVariable(gl.NewVariable(v[0]), gl.NewVariable(v[1])))
	}
	openings.Batches = append(openings.Batches, batch)
	checked.ObserveCheckedOpenings(openings)
	legacy.ObserveOpenings(openings)
	var final variables.PolynomialCoeffs
	for _, v := range c.Final {
		final.Coeffs = append(final.Coeffs, gl.NewQuadraticExtensionVariable(gl.NewVariable(v[0]), gl.NewVariable(v[1])))
	}
	caps := []variables.FriMerkleCap{{c.Hash}}
	config := types.FriConfig{NumQueryRounds: 2}
	a := checked.GetFriChallengesChecked(caps, final, gl.NewVariable(c.Pow), 12, config)
	b := legacy.GetFriChallenges(caps, final, gl.NewVariable(c.Pow), 12, config)
	for i := range a.FriAlpha {
		api.AssertIsEqual(a.FriAlpha[i].Limb, b.FriAlpha[i].Limb)
	}
	for i := range a.FriBetas {
		for j := range a.FriBetas[i] {
			api.AssertIsEqual(a.FriBetas[i][j].Limb, b.FriBetas[i][j].Limb)
		}
	}
	api.AssertIsEqual(a.FriPowResponse.Limb, b.FriPowResponse.Limb)
	for i := range a.FriQueryIndices {
		api.AssertIsEqual(a.FriQueryIndices[i].Limb, b.FriQueryIndices[i].Limb)
	}
	api.AssertIsEqual(checked.GetChallenge().Limb, legacy.GetChallenge().Limb)
	return nil
}

func TestCheckedTranscriptMatchesLegacy(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &checkedTranscriptCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	rng := rand.New(rand.NewSource(301))
	for sample := 0; sample < 12; sample++ {
		value := func() frontend.Variable {
			if sample == 0 {
				return 0
			}
			if sample == 1 {
				return new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
			}
			return new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
		}
		a := checkedTranscriptCircuit{Hash: rng.Uint64(), Pow: value()}
		if sample == 1 {
			a.Hash = new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
		}
		for i := range a.Openings {
			for j := range a.Openings[i] {
				a.Openings[i][j] = value()
			}
		}
		for i := range a.Final {
			for j := range a.Final[i] {
				a.Final[i][j] = value()
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
	// Checked proof inputs must reject p, even though the old reduce path
	// would map it to zero.
	for invalid := 0; invalid < 3; invalid++ {
		a := checkedTranscriptCircuit{Hash: 0, Pow: 0}
		for i := range a.Openings {
			for j := range a.Openings[i] {
				a.Openings[i][j] = 0
			}
		}
		for i := range a.Final {
			for j := range a.Final[i] {
				a.Final[i][j] = 0
			}
		}
		switch invalid {
		case 0:
			a.Openings[0][0] = gl.MODULUS
		case 1:
			a.Final[0][1] = gl.MODULUS
		case 2:
			a.Pow = gl.MODULUS
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(w); err == nil {
			t.Fatalf("accepted noncanonical field %d", invalid)
		}
	}
}

type bufferedMutationCircuit struct{ A, B frontend.Variable }

type shortTranscriptCircuit struct{ Hash, A, B frontend.Variable }

func (c *shortTranscriptCircuit) Define(api frontend.API) error {
	checked, legacy := NewChip(api), NewChip(api)
	checked.ObserveBN254Hash(c.Hash)
	legacy.ObserveElements(legacy.poseidonBN254Chip.ToVec(c.Hash))
	openings := fri.Openings{Batches: []fri.OpeningBatch{{Values: []gl.QuadraticExtensionVariable{
		gl.NewQuadraticExtensionVariable(gl.NewVariable(c.A), gl.NewVariable(c.B)),
	}}}}
	checked.ObserveCheckedOpenings(openings)
	legacy.ObserveOpenings(openings)
	api.AssertIsEqual(checked.GetChallenge().Limb, legacy.GetChallenge().Limb)
	return nil
}

func TestShortTranscriptGroth16(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &shortTranscriptCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
	w, err := frontend.NewWitness(&shortTranscriptCircuit{Hash: 123, A: 10, B: 20}, ecc.BN254.ScalarField())
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

func (c *bufferedMutationCircuit) Define(api frontend.API) error {
	challenger := NewChip(api)
	value := api.Add(c.A, c.B)
	var before []uint32
	api.Compiler().ToCanonicalVariable(value).Compress(&before)
	challenger.ObserveCheckedOpenings(fri.Openings{Batches: []fri.OpeningBatch{{Values: []gl.QuadraticExtensionVariable{gl.NewQuadraticExtensionVariable(gl.NewVariable(value), gl.Zero())}}}})
	api.MulAcc(value, c.A, 1)
	var after []uint32
	api.Compiler().ToCanonicalVariable(value).Compress(&after)
	if reflect.DeepEqual(before, after) {
		panic("test failed to mutate buffered expression")
	}
	challenger.GetChallenge()
	return nil
}
func TestCheckedBufferRejectsMutatedOutOfRange(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &bufferedMutationCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a, b  frontend.Variable
		valid bool
	}{{1, 0, true}, {new(big.Int).Sub(gl.MODULUS, big.NewInt(1)), 0, false}} {
		w, err := frontend.NewWitness(&bufferedMutationCircuit{tc.a, tc.b}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w)
		if (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}
