package poseidon

import gl "github.com/cf/gnark-plonky2-verifier/goldilocks"

func (c *GoldilocksChip) refFullRounds(state GoldilocksState, roundCounter *int) GoldilocksState {
	for i := 0; i < HALF_N_FULL_ROUNDS; i++ {
		state = c.refConstantLayer(state, roundCounter)
		state = c.sBoxLayer(state)
		state = c.mdsLayer(state)
		*roundCounter += 1
	}
	return state
}

func (c *GoldilocksChip) refPartialRounds(state GoldilocksState, roundCounter *int) GoldilocksState {
	if SPONGE_WIDTH != 12 || N_PARTIAL_ROUNDS != 22 || c.api.Compiler().FieldBitLen() < 209 {
		panic("lazy partial-round bounds require width 12, 22 rounds and a host field larger than 2^208")
	}
	state = c.refPartialFirstConstantLayer(state)
	state = c.mdsPartialLayerInit(state)

	for i := 0; i < N_PARTIAL_ROUNDS; i++ {
		state[0] = c.refSBoxMonomial(state[0])
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

func (c *GoldilocksChip) refConstantLayer(state GoldilocksState, roundCounter *int) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			roundConstant := ALL_ROUND_CONSTANTS[i+SPONGE_WIDTH*(*roundCounter)]
			state[i] = c.gl.Add(state[i], gl.NewVariable(roundConstant))
		}
	}
	return state
}

func (c *GoldilocksChip) refPartialFirstConstantLayer(state GoldilocksState) GoldilocksState {
	for i := 0; i < 12; i++ {
		if i < SPONGE_WIDTH {
			state[i] = c.gl.Add(state[i], gl.NewVariable(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]))
		}
	}
	return state
}

func (c *GoldilocksChip) refSBoxMonomial(x gl.Variable) gl.Variable {
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
