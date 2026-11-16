package poseidon

import (
	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark/frontend"
)

const HALF_N_FULL_ROUNDS = 4
const N_PARTIAL_ROUNDS = 22
const SPONGE_WIDTH = 12
const SPONGE_RATE = 8
const POSEIDON_GL_HASH_SIZE = 4

type GoldilocksState = [SPONGE_WIDTH]gl.Variable
type GoldilocksStateExtension = [SPONGE_WIDTH]gl.QuadraticExtensionVariable
type GoldilocksHashOut = [POSEIDON_GL_HASH_SIZE]gl.Variable

type GoldilocksChip struct {
	api frontend.API `gnark:"-"`
	gl  *gl.Chip     `gnark:"-"`
}

func NewGoldilocksChip(api frontend.API) *GoldilocksChip {
	return &GoldilocksChip{api: api, gl: gl.New(api)}
}

// The permutation function.
// The input state MUST have all it's elements be within Goldilocks field (e.g. this function will not reduce the input elements).
// The returned state's elements will all be within Goldilocks field.
func (c *GoldilocksChip) Poseidon(input GoldilocksState) GoldilocksState {
	state := input
	roundCounter := 0
	state = c.fullRoundsLazy(state, &roundCounter)
	state = c.partialRounds(state, &roundCounter)
	state = c.fullRoundsLazy(state, &roundCounter)
	return c.reduceMdsState(state)
}

// The input elements MUST have all it's elements be within Goldilocks field.
// The returned slice's elements will all be within Goldilocks field.
func (c *GoldilocksChip) HashNToMNoPad(input []gl.Variable, nbOutputs int) []gl.Variable {
	var state GoldilocksState

	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = gl.NewVariable(0)
	}

	for i := 0; i < len(input); i += SPONGE_RATE {
		for j := 0; j < SPONGE_RATE; j++ {
			if i+j < len(input) {
				state[j] = input[i+j]
			}
		}
		state = c.Poseidon(state)
	}

	var outputs []gl.Variable

	for {
		for i := 0; i < SPONGE_RATE; i++ {
			outputs = append(outputs, state[i])
			if len(outputs) == nbOutputs {
				return outputs
			}
		}
		state = c.Poseidon(state)
	}
}

// The input elements can be outside of the Goldilocks field.
// The returned slice's elements will all be within Goldilocks field.
func (c *GoldilocksChip) HashNoPad(input []gl.Variable) GoldilocksHashOut {
	var hash GoldilocksHashOut
	inputVars := []gl.Variable{}

	for i := 0; i < len(input); i++ {
		inputVars = append(inputVars, c.gl.Reduce(input[i]))
	}

	outputVars := c.HashNToMNoPad(inputVars, len(hash))
	for i := 0; i < len(hash); i++ {
		hash[i] = outputVars[i]
	}

	return hash
}

func (c *GoldilocksChip) ToVec(hash GoldilocksHashOut) []gl.Variable {
	return hash[:]
}

func (c *GoldilocksChip) fullRounds(state GoldilocksState, roundCounter *int) GoldilocksState {
	return c.reduceMdsState(c.fullRoundsLazy(state, roundCounter))
}

func (c *GoldilocksChip) fullRoundsLazy(state GoldilocksState, roundCounter *int) GoldilocksState {
	validateMdsCoefficients()
	for i := 0; i < HALF_N_FULL_ROUNDS; i++ {
		state = c.constantLayer(state, roundCounter)
		if i == 0 {
			// Each group starts from canonical lanes (the Poseidon input, or
			// the reduced partial-round output), so the first S-box input is
			// below 2p and admits tighter quotient bounds.
			for j := range state {
				state[j] = c.sBoxMonomialFirstRound(state[j])
			}
		} else {
			state = c.sBoxLayer(state)
		}
		state = c.mdsLayerLazy(state)
		*roundCounter += 1
	}
	return state
}

func (c *GoldilocksChip) partialRounds(state GoldilocksState, roundCounter *int) GoldilocksState {
	if SPONGE_WIDTH != 12 || N_PARTIAL_ROUNDS != 22 || c.api.Compiler().FieldBitLen() < 225 {
		panic("lazy Poseidon bounds require width 12, 22 rounds and a host field larger than 2^224")
	}
	state = c.partialFirstConstantLayer(state)
	state = c.mdsPartialLayerInit(state)

	for i := 0; i < N_PARTIAL_ROUNDS; i++ {
		if i == 0 {
			// The initial matrix may leave this lane below 265p.
			state[0] = c.sBoxMonomial(state[0])
		} else {
			// Every preceding fast MDS round reduces lane zero to [0, p).
			state[0] = c.sBoxMonomialCanonical(state[0])
		}
		state[0] = c.gl.AddNoReduce(state[0], canonicalRoundConstant(FAST_PARTIAL_ROUND_CONSTANTS[i]))
		state = c.mdsPartialLayerFast(state, i)
	}

	// Lanes 1..11 start canonical and gain at most 22 products of a value
	// below 2p and a uint64 coefficient. Each stays below 2^134, with a
	// quotient below 2^71.
	for i := 1; i < SPONGE_WIDTH; i++ {
		state[i] = c.gl.ReduceWithBound(state[i], 71)
	}

	*roundCounter += N_PARTIAL_ROUNDS

	return state
}

func (c *GoldilocksChip) constantLayer(state GoldilocksState, roundCounter *int) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)]
			state[i] = c.gl.AddNoReduce(state[i], canonicalRoundConstant(roundConstant))
		}
	}
	return state
}

// The lazy reductions below rely on every round constant being canonical.
func canonicalRoundConstant(v frontend.Variable) gl.Variable {
	constant, ok := v.(uint64)
	if !ok || constant >= gl.MODULUS.Uint64() {
		panic("Poseidon round constant must be a canonical uint64")
	}
	return gl.NewVariable(constant)
}

func (c *GoldilocksChip) ConstantLayerExtension(state GoldilocksStateExtension, roundCounter *int) GoldilocksStateExtension {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := gl.NewVariable(ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)])
			roundConstantQE := gl.NewQuadraticExtensionVariable(roundConstant, gl.Zero())
			state[i] = c.gl.AddExtension(state[i], roundConstantQE)
		}
	}
	return state
}

func (c *GoldilocksChip) sBoxMonomial(x gl.Variable) gl.Variable {
	return c.sBoxMonomialWithBounds(x, false)
}

// sBoxMonomialCanonical may only be used for an input already constrained
// to [0, p). Both x^3 and x*(x^3 mod p)^2 then have quotients below p^2.
func (c *GoldilocksChip) sBoxMonomialCanonical(x gl.Variable) gl.Variable {
	return c.sBoxMonomialWithBounds(x, true)
}

func (c *GoldilocksChip) sBoxMonomialWithBounds(x gl.Variable, canonical bool) gl.Variable {
	// A lazy MDS row is below 264p; adding a canonical constant gives x <
	// 265p. The x^3 quotient is < 265^3*p^2 < 2^153. After reducing x^3,
	// the x^7 quotient is < 265*p^2 < 2^137. The commitment-checker bounds
	// below require a host field larger than 2^224.
	if c.api.Compiler().FieldBitLen() < 225 {
		panic("Poseidon S-box bounds require a host field larger than 2^224")
	}
	x3Bits, x7Bits := uint64(153), uint64(137)
	if canonical {
		x3Bits, x7Bits = 128, 128
	}
	// The commitment range checker requires widths aligned to its 16-bit
	// base. The wider bounds still keep the equations below the host field.
	if !canonical {
		if _, native := c.api.(frontend.Rangechecker); !native {
			if _, committer := c.api.(frontend.Committer); committer {
				x3Bits, x7Bits = 160, 144
			}
		}
	}
	x2 := c.gl.MulNoReduce(x, x)
	x3 := c.gl.MulNoReduce(x, x2)
	x3 = c.gl.ReduceWithMaxBits(x3, x3Bits)
	x6 := c.gl.MulNoReduce(x3, x3)
	x7 := c.gl.MulNoReduce(x, x6)
	return c.gl.ReduceWithMaxBits(x7, x7Bits)
}

func (c *GoldilocksChip) SBoxMonomialExtension(x gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	x2 := c.gl.MulExtension(x, x)
	x4 := c.gl.MulExtension(x2, x2)
	x3 := c.gl.MulExtension(x, x2)
	return c.gl.MulExtension(x4, x3)
}

// sBoxMonomialFirstRound handles an input below 2p (a canonical element plus
// a canonical round constant). The x^3 quotient is below 8p² < 2^131 and the
// x^7 quotient below 2p² < 2^129.
func (c *GoldilocksChip) sBoxMonomialFirstRound(x gl.Variable) gl.Variable {
	if c.api.Compiler().FieldBitLen() < 225 {
		panic("Poseidon S-box bounds require a host field larger than 2^224")
	}
	x3Bits, x7Bits := uint64(131), uint64(129)
	// The commitment range checker requires widths aligned to its 16-bit
	// base. The wider bounds still keep the equations below the host field.
	if _, native := c.api.(frontend.Rangechecker); !native {
		if _, committer := c.api.(frontend.Committer); committer {
			x3Bits, x7Bits = 144, 144
		}
	}
	x2 := c.gl.MulNoReduce(x, x)
	x3 := c.gl.MulNoReduce(x, x2)
	x3 = c.gl.ReduceWithMaxBits(x3, x3Bits)
	x6 := c.gl.MulNoReduce(x3, x3)
	x7 := c.gl.MulNoReduce(x, x6)
	return c.gl.ReduceWithMaxBits(x7, x7Bits)
}

func (c *GoldilocksChip) sBoxLayer(state GoldilocksState) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.sBoxMonomial(state[i])
		}
	}
	return state
}

func (c *GoldilocksChip) SBoxLayerExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.SBoxMonomialExtension(state[i])
		}
	}
	return state
}

func (c *GoldilocksChip) mdsRowShf(r int, v GoldilocksState) gl.Variable {
	return c.gl.ReduceWithMaxBits(c.mdsRowShfLazy(r, v), 16)
}

func (c *GoldilocksChip) mdsRowShfLazy(r int, v GoldilocksState) gl.Variable {
	res := gl.Zero()

	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			res = c.gl.MulAddNoReduce(v[(i+r)%SPONGE_WIDTH], gl.NewVariable(MDS_MATRIX_CIRC_VARS[i]), res)
		}
	}

	res = c.gl.MulAddNoReduce(v[r], gl.NewVariable(MDS_MATRIX_DIAG_VARS[r]), res)
	return res
}

// Every full-round MDS input is canonical. Each lazy output is therefore
// below 264p, including the diagonal term; validate this compile-time bound.
func validateMdsCoefficients() {
	if SPONGE_WIDTH != 12 || len(MDS_MATRIX_CIRC_VARS) != SPONGE_WIDTH || len(MDS_MATRIX_DIAG_VARS) != SPONGE_WIDTH {
		panic("unexpected Poseidon MDS shape")
	}
	var sum uint64
	for _, v := range MDS_MATRIX_CIRC_VARS {
		n, ok := v.(uint64)
		if !ok || n > 264 || sum > 264-n {
			panic("Poseidon MDS coefficient exceeds lazy bound")
		}
		sum += n
	}
	for _, v := range MDS_MATRIX_DIAG_VARS {
		n, ok := v.(uint64)
		if !ok || n > 264-sum {
			panic("Poseidon MDS diagonal exceeds lazy bound")
		}
	}
}

func (c *GoldilocksChip) mdsLayerLazy(state GoldilocksState) GoldilocksState {
	var result GoldilocksState
	for i := range result {
		result[i] = c.mdsRowShfLazy(i, state)
	}
	return result
}

func (c *GoldilocksChip) reduceMdsState(state GoldilocksState) GoldilocksState {
	for i := range state {
		state[i] = c.gl.ReduceWithMaxBits(state[i], 16)
	}
	return state
}

func (c *GoldilocksChip) MdsRowShfExtension(r int, v GoldilocksStateExtension) gl.QuadraticExtensionVariable {
	validateExtensionMdsCoefficients()
	c.checkExtensionState(v)
	return c.mdsRowShfExtensionChecked(r, v)
}

// Extension MDS rows are two independent base-field linear combinations.
// The checked inputs are canonical and the coefficients sum to at most 264,
// so each quotient is below 264 and fits in 16 bits.
func (c *GoldilocksChip) mdsRowShfExtensionChecked(r int, v GoldilocksStateExtension) gl.QuadraticExtensionVariable {
	a, b := gl.Zero(), gl.Zero()
	for i := 0; i < SPONGE_WIDTH; i++ {
		coefficient := gl.NewVariable(MDS_MATRIX_CIRC[i])
		a = c.gl.MulAddNoReduce(v[(i+r)%SPONGE_WIDTH][0], coefficient, a)
		b = c.gl.MulAddNoReduce(v[(i+r)%SPONGE_WIDTH][1], coefficient, b)
	}
	coefficient := gl.NewVariable(MDS_MATRIX_DIAG[r])
	a = c.gl.MulAddNoReduce(v[r][0], coefficient, a)
	b = c.gl.MulAddNoReduce(v[r][1], coefficient, b)
	return gl.NewQuadraticExtensionVariable(c.gl.ReduceWithMaxBits(a, 16), c.gl.ReduceWithMaxBits(b, 16))
}

func validateExtensionMdsCoefficients() {
	if SPONGE_WIDTH != 12 || len(MDS_MATRIX_CIRC) != SPONGE_WIDTH || len(MDS_MATRIX_DIAG) != SPONGE_WIDTH {
		panic("unexpected extension Poseidon MDS shape")
	}
	var sum uint64
	for _, value := range MDS_MATRIX_CIRC {
		n, ok := value.(uint64)
		if !ok || n > 264 || sum > 264-n {
			panic("extension Poseidon MDS coefficient exceeds bound")
		}
		sum += n
	}
	for _, value := range MDS_MATRIX_DIAG {
		n, ok := value.(uint64)
		if !ok || n > 264-sum {
			panic("extension Poseidon MDS diagonal exceeds bound")
		}
	}
}

func (c *GoldilocksChip) checkExtensionState(state GoldilocksStateExtension) {
	// An 80-bit quotient times p is below 2^144, including an adversarial
	// witness. The partial matrices use only width-12 uint64 coefficients.
	if SPONGE_WIDTH != 12 || c.api.Compiler().FieldBitLen() < 145 {
		panic("extension Poseidon MDS requires width 12 and a host field larger than 2^144")
	}
	for _, value := range state {
		c.gl.RangeCheckQE(value)
	}
}

func extensionMatrixCoefficient(value frontend.Variable) gl.Variable {
	if _, ok := value.(uint64); !ok {
		panic("extension Poseidon MDS coefficient must be uint64")
	}
	return gl.NewVariable(value)
}

func (c *GoldilocksChip) mdsLayer(state_ GoldilocksState) GoldilocksState {
	var result GoldilocksState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = gl.NewVariable(0)
	}

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			result[r] = c.mdsRowShf(r, state_)
		}
	}

	return result
}

func (c *GoldilocksChip) MdsLayerExtension(state_ GoldilocksStateExtension) GoldilocksStateExtension {
	validateExtensionMdsCoefficients()
	c.checkExtensionState(state_)
	var result GoldilocksStateExtension

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			sum := c.mdsRowShfExtensionChecked(r, state_)
			result[r] = sum
		}
	}

	return result
}

func (c *GoldilocksChip) partialFirstConstantLayer(state GoldilocksState) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.gl.AddNoReduce(state[i], canonicalRoundConstant(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]))
		}
	}
	return state
}

func (c *GoldilocksChip) PartialFirstConstantLayerExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			fastPartialRoundConstant := gl.NewVariable(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i])
			fastPartialRoundConstantQE := gl.NewQuadraticExtensionVariable(fastPartialRoundConstant, gl.Zero())
			state[i] = c.gl.AddExtension(state[i], fastPartialRoundConstantQE)
		}
	}
	return state
}

func (c *GoldilocksChip) mdsPartialLayerInit(state GoldilocksState) GoldilocksState {
	var result GoldilocksState
	for i := 0; i < 12; i++ {
		result[i] = gl.Zero()
	}

	result[0] = state[0]

	for r := 1; r < 12; r++ {
		if r < SPONGE_WIDTH {
			for d := 1; d < 12; d++ {
				if d < SPONGE_WIDTH {
					t := FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1]
					result[d] = c.gl.MulAddNoReduce(state[r], gl.NewVariable(t), result[d])
				}
			}
		}
	}

	// result[0] is below 265p. Each other entry is a sum of 11 products of
	// elements below 265p and uint64 constants; its quotient is below 2^76.
	for i := 1; i < 12; i++ {
		result[i] = c.gl.ReduceWithBound(result[i], 76)
	}

	return result
}

func (c *GoldilocksChip) MdsPartialLayerInitExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	c.checkExtensionState(state)
	var result GoldilocksStateExtension
	result[0] = state[0]
	// Each coefficient sum has 11 products below p*2^64; its quotient is
	// below 11*2^64, which fits in 80 bits.
	for d := 1; d < SPONGE_WIDTH; d++ {
		a, b := gl.Zero(), gl.Zero()
		for r := 1; r < SPONGE_WIDTH; r++ {
			coefficient := extensionMatrixCoefficient(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1])
			a = c.gl.MulAddNoReduce(state[r][0], coefficient, a)
			b = c.gl.MulAddNoReduce(state[r][1], coefficient, b)
		}
		result[d] = gl.NewQuadraticExtensionVariable(c.gl.ReduceWithMaxBits(a, 80), c.gl.ReduceWithMaxBits(b, 80))
	}

	return result
}

func (c *GoldilocksChip) mdsPartialLayerFast(state GoldilocksState, r int) GoldilocksState {
	dSum := gl.Zero()
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_W_HATS_VARS[r][i-1]
			if _, ok := t.(uint64); !ok {
				panic("lazy partial-round weight must be a uint64 constant")
			}
			dSum = c.gl.MulAddNoReduce(state[i], gl.NewVariable(t), dSum)
		}
	}

	if _, ok := MDS0TO0_VAR.(uint64); !ok {
		panic("lazy partial-round diagonal must be a uint64 constant")
	}
	d := c.gl.MulAddNoReduce(state[0], gl.NewVariable(MDS0TO0_VAR), dSum)
	// The 11 lazy lanes are each <2^134, and each coefficient is <2^64.
	// The sum is <2^202, so the quotient is <2^139 and no host-field
	// wraparound is possible (including quotient * Goldilocks modulus).
	d = c.gl.ReduceWithBound(d, 139)

	var result GoldilocksState
	for i := 0; i < SPONGE_WIDTH; i++ {
		result[i] = gl.NewVariable(0)
	}

	result[0] = d

	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := FAST_PARTIAL_ROUND_VS[r][i-1]
			if _, ok := t.(uint64); !ok {
				panic("lazy partial-round coefficient must be a uint64 constant")
			}
			result[i] = c.gl.MulAddNoReduce(state[0], gl.NewVariable(t), state[i])
		}
	}

	return result
}

func (c *GoldilocksChip) MdsPartialLayerFastExtension(state GoldilocksStateExtension, r int) GoldilocksStateExtension {
	c.checkExtensionState(state)
	// The first lane sums 12 products below p*2^64. Each remaining lane
	// is a single such product plus a canonical field element.
	a, b := gl.Zero(), gl.Zero()
	for i := 1; i < SPONGE_WIDTH; i++ {
		coefficient := extensionMatrixCoefficient(FAST_PARTIAL_ROUND_W_HATS[r][i-1])
		a = c.gl.MulAddNoReduce(state[i][0], coefficient, a)
		b = c.gl.MulAddNoReduce(state[i][1], coefficient, b)
	}
	coefficient := extensionMatrixCoefficient(MDS0TO0)
	a = c.gl.MulAddNoReduce(state[0][0], coefficient, a)
	b = c.gl.MulAddNoReduce(state[0][1], coefficient, b)
	var result GoldilocksStateExtension
	result[0] = gl.NewQuadraticExtensionVariable(c.gl.ReduceWithMaxBits(a, 80), c.gl.ReduceWithMaxBits(b, 80))
	for i := 1; i < SPONGE_WIDTH; i++ {
		coefficient = extensionMatrixCoefficient(FAST_PARTIAL_ROUND_VS[r][i-1])
		a = c.gl.MulAddNoReduce(state[0][0], coefficient, state[i][0])
		b = c.gl.MulAddNoReduce(state[0][1], coefficient, state[i][1])
		result[i] = gl.NewQuadraticExtensionVariable(c.gl.ReduceWithMaxBits(a, 80), c.gl.ReduceWithMaxBits(b, 80))
	}

	return result
}
