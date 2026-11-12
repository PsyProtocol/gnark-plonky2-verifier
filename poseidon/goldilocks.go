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
	state = c.fullRounds(state, &roundCounter)
	state = c.partialRounds(state, &roundCounter)
	state = c.fullRounds(state, &roundCounter)
	return state
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
	for i := 0; i < HALF_N_FULL_ROUNDS; i++ {
		state = c.constantLayer(state, roundCounter)
		state = c.sBoxLayer(state)
		state = c.mdsLayer(state)
		*roundCounter += 1
	}
	return state
}

func (c *GoldilocksChip) partialRounds(state GoldilocksState, roundCounter *int) GoldilocksState {
	if SPONGE_WIDTH != 12 || N_PARTIAL_ROUNDS != 22 || c.api.Compiler().FieldBitLen() < 209 {
		panic("lazy partial-round bounds require width 12, 22 rounds and a host field larger than 2^208")
	}
	state = c.partialFirstConstantLayer(state)
	state = c.mdsPartialLayerInit(state)

	for i := 0; i < N_PARTIAL_ROUNDS; i++ {
		state[0] = c.sBoxMonomial(state[0])
		state[0] = c.gl.Add(state[0], gl.NewVariable(FAST_PARTIAL_ROUND_CONSTANTS[i]))
		state = c.mdsPartialLayerFast(state, i)
	}

	// Lanes 1..11 start canonical and gain at most 22 products of two
	// uint64-sized values; each is below 2^133 and its quotient is <2^70.
	for i := 1; i < SPONGE_WIDTH; i++ {
		state[i] = c.gl.ReduceWithMaxBits(state[i], 80)
	}

	*roundCounter += N_PARTIAL_ROUNDS

	return state
}

func (c *GoldilocksChip) constantLayer(state GoldilocksState, roundCounter *int) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)]
			state[i] = c.gl.Add(state[i], gl.NewVariable(roundConstant))
		}
	}
	return state
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
	// The S-box input and each reduced intermediate are canonical Goldilocks
	// elements. Each unreduced product is therefore less than p^3, so its
	// quotient by p is less than p^2 < 2^128. Keep the bound aligned to 16
	// bits for the commitment-based range checker as well.
	const quotientBits = 128
	x2 := c.gl.MulNoReduce(x, x)
	x3 := c.gl.MulNoReduce(x, x2)
	x3 = c.gl.ReduceWithMaxBits(x3, quotientBits)
	x6 := c.gl.MulNoReduce(x3, x3)
	x7 := c.gl.MulNoReduce(x, x6)
	return c.gl.ReduceWithMaxBits(x7, quotientBits)
}

func (c *GoldilocksChip) SBoxMonomialExtension(x gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	x2 := c.gl.MulExtension(x, x)
	x4 := c.gl.MulExtension(x2, x2)
	x3 := c.gl.MulExtension(x, x2)
	return c.gl.MulExtension(x4, x3)
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
	res := gl.Zero()

	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			res = c.gl.MulAddNoReduce(v[(i+r)%SPONGE_WIDTH], gl.NewVariable(MDS_MATRIX_CIRC_VARS[i]), res)
		}
	}

	res = c.gl.MulAddNoReduce(v[r], gl.NewVariable(MDS_MATRIX_DIAG_VARS[r]), res)
	// All state elements are canonical and the sum of these matrix
	// coefficients is at most 264, so the quotient is less than 2^16.
	return c.gl.ReduceWithMaxBits(res, 16)
}

func (c *GoldilocksChip) MdsRowShfExtension(r int, v GoldilocksStateExtension) gl.QuadraticExtensionVariable {
	res := gl.ZeroExtension()

	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			matrixVal := gl.NewVariable(MDS_MATRIX_CIRC[i])
			matrixValQE := gl.NewQuadraticExtensionVariable(matrixVal, gl.Zero())
			res1 := c.gl.MulExtension(v[(i+r)%SPONGE_WIDTH], matrixValQE)
			res = c.gl.AddExtension(res, res1)
		}
	}

	matrixVal := gl.NewVariable(MDS_MATRIX_DIAG[r])
	matrixValQE := gl.NewQuadraticExtensionVariable(matrixVal, gl.Zero())
	res = c.gl.AddExtension(res, c.gl.MulExtension(v[r], matrixValQE))
	return res
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
	var result GoldilocksStateExtension

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			sum := c.MdsRowShfExtension(r, state_)
			result[r] = sum
		}
	}

	return result
}

func (c *GoldilocksChip) partialFirstConstantLayer(state GoldilocksState) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.gl.Add(state[i], gl.NewVariable(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]))
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

	// result[0] is already a canonical state element. Each other entry is a
	// sum of 11 products of canonical elements and uint64 constants; its
	// quotient is less than 11 * 2^64 < 2^80.
	for i := 1; i < 12; i++ {
		result[i] = c.gl.ReduceWithMaxBits(result[i], 80)
	}

	return result
}

func (c *GoldilocksChip) MdsPartialLayerInitExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	var result GoldilocksStateExtension
	for i := 0; i < 12; i++ {
		result[i] = gl.ZeroExtension()
	}

	result[0] = state[0]

	for r := 1; r < 12; r++ {
		if r < SPONGE_WIDTH {
			for d := 1; d < 12; d++ {
				if d < SPONGE_WIDTH {
					t := gl.NewVariable(FAST_PARTIAL_ROUND_INITIAL_MATRIX[r-1][d-1])
					tQE := gl.NewQuadraticExtensionVariable(t, gl.Zero())
					result[d] = c.gl.AddExtension(result[d], c.gl.MulExtension(state[r], tQE))
				}
			}
		}
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
	// The 11 lazy lanes are each <2^133, and each coefficient is <2^64.
	// The sum is <2^201, so the quotient is <2^138 and no host-field
	// wraparound is possible (including quotient * Goldilocks modulus).
	d = c.gl.ReduceWithMaxBits(d, 144)

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
	s0 := state[0]
	mds0to0 := gl.NewVariable(MDS0TO0)
	mds0to0QE := gl.NewQuadraticExtensionVariable(mds0to0, gl.Zero())
	d := c.gl.MulExtension(s0, mds0to0QE)
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := gl.NewVariable(FAST_PARTIAL_ROUND_W_HATS[r][i-1])
			tQE := gl.NewQuadraticExtensionVariable(t, gl.Zero())
			d = c.gl.AddExtension(d, c.gl.MulExtension(state[i], tQE))
		}
	}

	var result GoldilocksStateExtension
	result[0] = d
	for i := 1; i < 12; i++ {
		if i < SPONGE_WIDTH {
			t := gl.NewVariable(FAST_PARTIAL_ROUND_VS[r][i-1])
			tQE := gl.NewQuadraticExtensionVariable(t, gl.Zero())
			result[i] = c.gl.AddExtension(c.gl.MulExtension(state[0], tQE), state[i])
		}
	}

	return result
}
