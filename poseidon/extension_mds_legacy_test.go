package poseidon

import gl "github.com/cf/gnark-plonky2-verifier/goldilocks"

func (c *GoldilocksChip) legacyMdsRowShfExtension(r int, v GoldilocksStateExtension) gl.QuadraticExtensionVariable {
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

func (c *GoldilocksChip) legacyMdsLayerExtension(state_ GoldilocksStateExtension) GoldilocksStateExtension {
	var result GoldilocksStateExtension

	for r := 0; r < 12; r++ {
		if r < SPONGE_WIDTH {
			sum := c.legacyMdsRowShfExtension(r, state_)
			result[r] = sum
		}
	}

	return result
}

func (c *GoldilocksChip) legacyMdsPartialLayerInitExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
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

func (c *GoldilocksChip) legacyMdsPartialLayerFastExtension(state GoldilocksStateExtension, r int) GoldilocksStateExtension {
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
