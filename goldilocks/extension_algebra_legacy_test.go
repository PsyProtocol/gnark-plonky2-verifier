package goldilocks

func (p *Chip) legacyMulExtensionAlgebra(
	a QuadraticExtensionAlgebraVariable,
	b QuadraticExtensionAlgebraVariable,
) QuadraticExtensionAlgebraVariable {
	var inner [D][]QuadraticExtensionAlgebraVariable
	var innerW [D][]QuadraticExtensionAlgebraVariable

	for i := 0; i < D; i++ {
		for j := 0; j < D-i; j++ {
			idx := (i + j) % D
			inner[idx] = append(inner[idx], QuadraticExtensionAlgebraVariable{a[i], b[j]})
		}
		for j := D - i; j < D; j++ {
			idx := (i + j) % D
			innerW[idx] = append(innerW[idx], QuadraticExtensionAlgebraVariable{a[i], b[j]})
		}
	}

	var product QuadraticExtensionAlgebraVariable
	for i := 0; i < D; i++ {
		acc := p.InnerProductExtension(NewVariable(W), ZeroExtension(), innerW[i])
		product[i] = p.InnerProductExtension(One(), acc, inner[i])
	}

	return product
}
