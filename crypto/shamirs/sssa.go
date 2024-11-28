package shamirs

import (
	"encoding/hex"
	"errors"
	"math/big"
)

var (
	ErrCannotRequireMoreShares = errors.New("cannot require more shares then existing")
	ErrOneOfTheSharesIsInvalid = errors.New("one of the shares is invalid")
	ErrRepeatedShares          = errors.New("shares is repeated")
)

const (
	DefaultPrimeStr = "115792089237316195423570985008687907853269984665640564039457584007913129639747"
)

// Create 分拆秘密 shares 总的份数， minimum 恢复时需要的最小数量
func Create(minimum int, shares int, raw []byte) ([][]byte, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.
	if minimum > shares {
		return nil, ErrCannotRequireMoreShares
	}

	// Convert the secret to its respective 256-bit big.Int representation
	var secret []*big.Int = splitByteToInt(raw)

	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// List of currently used numbers in the polynomial
	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))

	// Create the polynomial of degree (minimum - 1); that is, the highest
	// order term is (minimum-1), though as there is a constant term with
	// order 0, there are (minimum) number of coefficients.
	//
	// However, the polynomial object is a 2d array, because we are constructing
	// a different polynomial for each part of the secret
	// polynomial[parts][minimum]
	var polynomial [][]*big.Int = make([][]*big.Int, len(secret))
	for i := range polynomial {
		polynomial[i] = make([]*big.Int, minimum)
		polynomial[i][0] = secret[i]

		for j := range polynomial[i][1:] {
			// Each coefficient should be unique
			number := random()
			for inNumbers(numbers, number) {
				number = random()
			}
			numbers = append(numbers, number)

			polynomial[i][j+1] = number
		}
	}

	// Create the secrets object; this holds the (x, y) points of each share.
	// Again, because secret is an array, each share could have multiple parts
	// over which we are computing Shamir's Algorithm. The last dimension is
	// always two, as it is storing an x, y pair of points.
	//
	// Note: this array is technically unnecessary due to creating result
	// in the inner loop. Can disappear later if desired. [TODO]
	//
	// secrets[shares][parts][2]
	var secrets [][][]*big.Int = make([][][]*big.Int, shares)
	var result [][]byte = make([][]byte, shares)

	// For every share...
	for i := range secrets {
		secrets[i] = make([][]*big.Int, len(secret))
		// ...and every part of the secret...
		for j := range secrets[i] {
			secrets[i][j] = make([]*big.Int, 2)

			// ...generate a new x-coordinate...
			number := random()
			for inNumbers(numbers, number) {
				number = random()
			}
			numbers = append(numbers, number)

			// ...and evaluate the polynomial at that point...
			secrets[i][j][0] = number
			secrets[i][j][1] = evaluatePolynomial(polynomial[j], number)

			// ...add it to results...
			//result[i] += toBase64(secrets[i][j][0])
			result[i] = append(result[i], toBytes(secrets[i][j][0])...)
			result[i] = append(result[i], toBytes(secrets[i][j][1])...)
			//result[i] += toBase64(secrets[i][j][1])
		}
	}

	// ...and return!
	return result, nil
}

// Combine 恢复秘密
func Combine(shares [][]byte) ([]byte, error) {
	sharesMap := make(map[string]bool)
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// For each share...
	for i := range shares {
		flag := sharesMap[hex.EncodeToString(shares[i])]
		if flag {
			return nil, ErrRepeatedShares
		}
		sharesMap[hex.EncodeToString(shares[i])] = true
		// ...ensure that it is valid...
		if IsValidShare(shares[i]) == false {
			return nil, ErrOneOfTheSharesIsInvalid
		}

		// ...find the number of parts it represents...
		share := shares[i]
		count := len(share) / 64
		secrets[i] = make([][]*big.Int, count)

		// ...and for each part, find the x,y pair...
		for j := range secrets[i] {
			cshare := share[j*64 : (j+1)*64]
			secrets[i][j] = make([]*big.Int, 2)
			// ...decoding from base 64.
			secrets[i][j][0] = fromBytes(cshare[0:32])
			secrets[i][j][1] = fromBytes(cshare[32:])
		}
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret []*big.Int = make([]*big.Int, len(secrets[0]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		// ...and every share...
		for i := range secrets { // LPI sum loop
			// ...remember the current x and y values...
			origin := secrets[i][j][0]
			originy := secrets[i][j][1]
			numerator := big.NewInt(1)   // LPI numerator
			denominator := big.NewInt(1) // LPI denominator
			// ...and for every other point...
			for k := range secrets { // LPI product loop
				if k != i {
					// ...combine them via half products...
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			// LPI product
			// ...multiply together the points (y)(numerator)(denominator)^-1...
			working := big.NewInt(0).Set(originy)
			working = working.Mul(working, numerator)
			working = working.Mul(working, modInverse(denominator))

			// LPI sum
			secret[j] = secret[j].Add(secret[j], working)
			secret[j] = secret[j].Mod(secret[j], prime)
		}
	}

	// ...and return the result!
	return mergeIntToByte(secret), nil
}

// IsValidShare 是否正确的分片
func IsValidShare(candidate []byte) bool {
	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	if len(candidate)%64 != 0 {
		return false
	}

	count := len(candidate) / 32
	for j := 0; j < count; j++ {
		part := candidate[j*32 : (j+1)*32]
		//	decode := fromBase64(part)
		decode := fromBytes(part)
		if decode.Cmp(big.NewInt(0)) == -1 || decode.Cmp(prime) == 1 {
			return false
		}
	}

	return true
}