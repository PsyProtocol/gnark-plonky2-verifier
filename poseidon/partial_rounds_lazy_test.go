package poseidon

import (
	"math/big"
	"math/rand"
	"testing"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/backend/groth16"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
)

type lazyComparisonCircuit struct {
	In [SPONGE_WIDTH]frontend.Variable
}

func (c *lazyComparisonCircuit) Define(api frontend.API) error {
	g := gl.New(api)
	var input GoldilocksState
	for i := range input {
		input[i] = gl.NewVariable(c.In[i])
		g.RangeCheck(input[i])
	}
	chip := NewGoldilocksChip(api)
	current := chip.Poseidon(input)
	rc := 0
	legacy := chip.fullRounds(input, &rc)
	legacy = chip.partialRoundsLegacy(legacy, &rc)
	legacy = chip.fullRounds(legacy, &rc)
	for i := range current {
		api.AssertIsEqual(current[i].Limb, legacy[i].Limb)
	}
	return nil
}
func TestLazyPartialRoundsMatchLegacy(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lazyComparisonCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	rng := rand.New(rand.NewSource(61))
	for k := 0; k < 36; k++ {
		a := &lazyComparisonCircuit{}
		for i := range a.In {
			switch k {
			case 0:
				a.In[i] = 0
			case 1:
				a.In[i] = 1
			case 2:
				a.In[i] = max
			case 3:
				if i%2 == 0 {
					a.In[i] = max
				} else {
					a.In[i] = 0
				}
			default:
				a.In[i] = new(big.Int).Mod(new(big.Int).SetUint64(rng.Uint64()), gl.MODULUS)
			}
		}
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if e = ccs.IsSolved(w); e != nil {
			t.Fatalf("case %d: %v", k, e)
		}
	}
}
func TestLazyPartialRoundBounds(t *testing.T) {
	if N_PARTIAL_ROUNDS != 22 || SPONGE_WIDTH != 12 {
		t.Fatal("reassess lazy reduction bounds")
	}
	for r := 0; r < N_PARTIAL_ROUNDS; r++ {
		for i := 0; i < 11; i++ {
			if _, ok := FAST_PARTIAL_ROUND_VS[r][i].(uint64); !ok {
				t.Fatalf("round %d VS %d not uint64", r, i)
			}
			if _, ok := FAST_PARTIAL_ROUND_W_HATS_VARS[r][i].(uint64); !ok {
				t.Fatalf("round %d W %d not uint64", r, i)
			}
		}
	}
	if _, ok := MDS0TO0_VAR.(uint64); !ok {
		t.Fatal("MDS0TO0 not uint64")
	}
	max := new(big.Int).Sub(gl.MODULUS, big.NewInt(1))
	max64 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	// Each round adds a canonical S-box output and a canonical constant.
	lane := new(big.Int).Mul(new(big.Int).Mul(max, big.NewInt(2)), max64)
	lane.Mul(lane, big.NewInt(N_PARTIAL_ROUNDS))
	lane.Add(lane, max)
	if lane.BitLen() > 134 {
		t.Fatalf("lane bound bit length %d", lane.BitLen())
	}
	if q := new(big.Int).Quo(lane, gl.MODULUS); q.BitLen() > 71 {
		t.Fatalf("lane quotient bit length %d", q.BitLen())
	}
	d := new(big.Int).Mul(lane, max64)
	d.Mul(d, big.NewInt(11))
	d.Add(d, new(big.Int).Mul(new(big.Int).Mul(max, big.NewInt(2)), max64))
	if d.BitLen() > 202 {
		t.Fatalf("d bound bit length %d", d.BitLen())
	}
	q := new(big.Int).Quo(d, gl.MODULUS)
	if q.BitLen() > 139 {
		t.Fatalf("quotient bit length %d", q.BitLen())
	}
	initial := new(big.Int).Mul(gl.MODULUS, big.NewInt(265*11))
	initial.Mul(initial, max64)
	if q := new(big.Int).Quo(initial, gl.MODULUS); q.BitLen() > 76 {
		t.Fatalf("initial matrix quotient bit length %d", q.BitLen())
	}
	constraintMax := new(big.Int).Lsh(new(big.Int).Set(gl.MODULUS), 144)
	constraintMax.Sub(constraintMax, big.NewInt(1))
	if constraintMax.Cmp(ecc.BN254.ScalarField()) >= 0 {
		t.Fatal("reduction equality may wrap in host field")
	}
}
func TestLazyPartialRoundsGroth16(t *testing.T) {
	ccs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lazyComparisonCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	var a lazyComparisonCircuit
	for i := range a.In {
		a.In[i] = i + 1
	}
	w, e := frontend.NewWitness(&a, ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	pk, vk, e := groth16.Setup(ccs)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := groth16.Prove(ccs, pk, w)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := w.Public()
	if e != nil {
		t.Fatal(e)
	}
	if e = groth16.Verify(proof, vk, pub); e != nil {
		t.Fatal(e)
	}
	if len(ccs.GetCommitments().CommitmentIndexes()) != 0 {
		t.Fatal("unexpected commitment")
	}
}

func (c *GoldilocksChip) partialRoundsLegacy(state GoldilocksState, roundCounter *int) GoldilocksState {
	state = c.partialFirstConstantLayer(state)
	state = c.mdsPartialLayerInit(state)

	for i := 0; i < N_PARTIAL_ROUNDS; i++ {
		state[0] = c.sBoxMonomial(state[0])
		state[0] = c.gl.Add(state[0], gl.NewVariable(FAST_PARTIAL_ROUND_CONSTANTS[i]))
		state = c.mdsPartialLayerFastLegacy(state, i)
	}

	*roundCounter += N_PARTIAL_ROUNDS

	return state
}

func (c *GoldilocksChip) mdsPartialLayerFastLegacy(state GoldilocksState, r int) GoldilocksState {
	dSum := gl.Zero()
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_W_HATS_VARS[r][i-1]
			dSum = c.gl.MulAddNoReduce(state[i], gl.NewVariable(t), dSum)
		}
	}

	d := c.gl.MulAddNoReduce(state[0], gl.NewVariable(MDS0TO0_VAR), dSum)
	// The sum contains at most 12 products of canonical state elements and
	// uint64 constants, so the quotient is less than 2^80.
	d = c.gl.ReduceWithMaxBits(d, 80)

	var result GoldilocksState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = gl.NewVariable(0)
	}

	result[0] = d

	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_VS[r][i-1]
			result[i] = c.gl.MulAddNoReduce(state[0], gl.NewVariable(t), state[i])
		}
	}

	// result[0] is d, which was already reduced above. The remaining entries
	// are one product plus a canonical element and fit the same quotient bound.
	for i := 1; i < len(state); i++ {
		result[i] = c.gl.ReduceWithMaxBits(result[i], 80)
	}

	return result
}

type lazyGuardCircuit struct {
	In [SPONGE_WIDTH]frontend.Variable
}

func (c *lazyGuardCircuit) Define(api frontend.API) error {
	var state GoldilocksState
	for i := range state {
		state[i] = gl.NewVariable(c.In[i])
	}
	counter := 0
	NewGoldilocksChip(api).partialRounds(state, &counter)
	return nil
}
func TestLazyPartialRoundGuardsRejectNonUint64Constants(t *testing.T) {
	tests := []struct {
		name string
		get  func() frontend.Variable
		set  func(frontend.Variable)
	}{
		{"VS", func() frontend.Variable { return FAST_PARTIAL_ROUND_VS[0][0] }, func(x frontend.Variable) { FAST_PARTIAL_ROUND_VS[0][0] = x }},
		{"weight", func() frontend.Variable { return FAST_PARTIAL_ROUND_W_HATS_VARS[0][0] }, func(x frontend.Variable) { FAST_PARTIAL_ROUND_W_HATS_VARS[0][0] = x }},
		{"diagonal", func() frontend.Variable { return MDS0TO0_VAR }, func(x frontend.Variable) { MDS0TO0_VAR = x }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := tc.get()
			defer tc.set(old)
			tc.set(new(big.Int).Lsh(big.NewInt(1), 64))
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lazyGuardCircuit{}); err == nil {
				t.Fatal("accepted a coefficient larger than 64 bits")
			}
		})
	}
}
