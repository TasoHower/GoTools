// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/bmizerany/assert"
)

// TestEd25519 验证 (a + b)*B = a*B + b*B
func TestEd25519(t *testing.T) {
	a := make([]byte, 32)
	rand.Read(a)
	a[0] &= 248
	a[31] &= 127 - 32
	a[31] |= 64

	b := make([]byte, 32)
	rand.Read(b)
	b[0] &= 248
	b[31] = 0

	var A ExtendedGroupElement
	var a32 [32]byte
	copy(a32[:], a[:])
	GeScalarMultBase(&A, &a32)

	var B ExtendedGroupElement
	var b32 [32]byte
	copy(b32[:], b[:])
	GeScalarMultBase(&B, &b32)

	var BB CachedGroupElement
	B.ToCached(&BB)
	var R CompletedGroupElement
	GeAdd(&R, &A, &BB)
	//GeAdd得到结果
	var R1 ExtendedGroupElement
	R.ToExtended(&R1)

	var af FieldElement
	var bf FieldElement
	var rf FieldElement
	FeFromBytes(&af, &a32)
	FeFromBytes(&bf, &b32)
	FeAdd(&rf, &af, &bf)

	var aa32 [32]byte
	FeToBytes(&aa32, &rf)

	//（a+b)*B 得到结果
	var R2 ExtendedGroupElement
	GeScalarMultBase(&R2, &aa32)

	var R3 ProjectiveGroupElement
	var aa [32]byte
	aa[0] = 1

	//1*A+b*B 得到结果
	GeDoubleScalarMultVartime(&R3, &aa, &A, &b32)

	var r1 [32]byte
	var r2 [32]byte
	var r3 [32]byte
	R1.ToBytes(&r1)
	R2.ToBytes(&r2)
	R3.ToBytes(&r3)

	assert.Equal(t, r1, r2)
	assert.Equal(t, r1, r3)
	fmt.Println(r1)
	fmt.Println(r2)
	fmt.Println(r3)
}
