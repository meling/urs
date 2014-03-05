// Copyright 2014 Hein Meling and Haibin Zhang. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package urs implements Unique Ring Signatures, as defined in 
// short version: http://csiflabs.cs.ucdavis.edu/~hbzhang/romring.pdf
// full version: http://eprint.iacr.org/2012/577.pdf
package urs

// References:
//   [NSA]: Suite B implementer's guide to FIPS 186-3,
//     http://www.nsa.gov/ia/_files/ecdsa.pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/download/aid-780/sec1-v2.pdf

import (
	"crypto/elliptic"
	"crypto/sha256"
	"bytes"
	"io"
	"fmt"
	"math/big"
)

// PublicKey corresponds to a ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey corresponds to a ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// PublicKeyRing is a list of public keys.
type PublicKeyRing struct {
	Ring []PublicKey
}

// NewPublicKeyRing creates a new public key ring.
// All keys added to the ring must use the same curve.
func NewPublicKeyRing(cap uint) *PublicKeyRing {
	return &PublicKeyRing{make([]PublicKey, 0, cap)}
}

// Add adds a public key, pub to the ring.
// All keys added to the ring must use the same curve.
func (r *PublicKeyRing) Add(pub PublicKey) {
	r.Ring = append(r.Ring, pub)
}

// Len returns the length of ring.
func (r *PublicKeyRing) Len() int {
	return len(r.Ring)
}

// Bytes returns the public key ring as a byte slice.
func (r *PublicKeyRing) Bytes() (b []byte) {
	for _, pub := range r.Ring {
		b = append(b, pub.X.Bytes()...)
		b = append(b, pub.Y.Bytes()...)
	}
	return
}

func (k PublicKey) String() string {
	return fmt.Sprintf("X(%s)\nY(%s)\n", k.X, k.Y)
}

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, crand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(crand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (priv *PrivateKey, err error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return
	}

	priv = new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

type RingSign struct {
	Hsx, Hsy *big.Int
	C, T []*big.Int
}

// this is just for debugging; we probably don't want this for anything else
func (k *RingSign) String() string {
	var buf bytes.Buffer
	for i := 0; i < len(k.C); i++ {
		buf.WriteString(fmt.Sprintf("C[%d]: ", i))
		buf.WriteString(k.C[i].String())
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("T[%d]: ", i))
		buf.WriteString(k.T[i].String())
		buf.WriteString("\n")
	}
	return fmt.Sprintf("URS:\nHx=%s\nHy=%s\n%s", k.Hsx, k.Hsy, buf.String())
}

func hashG(curve elliptic.Curve, m []byte) (hx, hy *big.Int) {
	h := sha256.New()
	h.Write(m)
	d := h.Sum(nil)
	hx, hy = curve.ScalarBaseMult(d)
	return
}

func hashq(m []byte) (d []byte) {
	h := sha256.New()
	h.Write(m)
	d = h.Sum(nil)
	return
}

// Sign signs an arbitrary length message (which should NOT be the hash of a
// larger message) using the private key, priv and the public key ring, ring. 
// It returns the signature as a struct of type RingSign.
// The security of the private key depends on the entropy of rand.
// The public keys in the ring must all be using the same curve.
func Sign(rand io.Reader, priv *PrivateKey, R *PublicKeyRing, m []byte) (rs *RingSign, err error) {
	s := R.Len()
	ax := make([]*big.Int, s, s)
	ay := make([]*big.Int, s, s)
	bx := make([]*big.Int, s, s)
	by := make([]*big.Int, s, s)
	c := make([]*big.Int, s, s)
	t := make([]*big.Int, s, s)
	pub := priv.PublicKey
	curve := pub.Curve
	N := curve.Params().N

	mR := append(m, R.Bytes()...)
	hx, hy := hashG(curve, mR) // H(mR)
	hsx, hsy := curve.ScalarMult(hx, hy, priv.D.Bytes()) // Step 4: H(mR)^xi

	var id int
	sum := new(big.Int).SetInt64(0)
	for j := 0; j < s; j++ {
		if R.Ring[j] == pub {
			id = j
		} else {
			c[j], err = randFieldElement(curve, rand)
			if err != nil {
				return nil, err
			}
			t[j], err = randFieldElement(curve, rand)
			if err != nil {
				return nil, err
			}
			ax1, ay1 := curve.ScalarBaseMult(t[j].Bytes()) // g^tj
			ax2, ay2 := curve.ScalarMult(R.Ring[j].X, R.Ring[j].Y, c[j].Bytes()) // yj^cj
			ax[j], ay[j] = curve.Add(ax1, ay1, ax2, ay2)

			w := new(big.Int)
			w.Mul(priv.D, c[j])
			w.Add(w, t[j])
			w.Mod(w, N)
			bx[j], by[j] = curve.ScalarMult(hx, hy, w.Bytes())

			sum.Add(sum, c[j]) // Sum needed in Step 3 of the algorithm
		}
	}
	// Compute stuff for my public key at index id
	var r *big.Int
	r, err = randFieldElement(curve, rand)
	if err != nil {
		return nil, err
	}
	rb := r.Bytes()
	ax[id], ay[id] = curve.ScalarBaseMult(rb) // g^r
	bx[id], by[id] = curve.ScalarMult(hx, hy, rb) // H(mR)^r

	mRab := make([]byte, 0)
	mRab = append(mRab, mR...)
	for i := 0; i < s; i++ {
		mRab = append(mRab, ax[i].Bytes()...)
		mRab = append(mRab, ay[i].Bytes()...)
		mRab = append(mRab, bx[i].Bytes()...)
		mRab = append(mRab, by[i].Bytes()...)
	}
	// hashmRab := hashToInt(hashq(mRab), curve)
	// Step 3, part 1: c_i = H(m,R,{a,b}) - sum(c_j) mod N
	hashmRab := new(big.Int).SetBytes(hashq(mRab))
	c[id] = new(big.Int).SetInt64(0)
	c[id].Sub(hashmRab, sum)
	c[id].Mod(c[id], N)

	// Step 3, part 2: t_i = r_i - c_i x x_i mod N
	cx := new(big.Int)
	cx.Mul(priv.D, c[id])
	t[id] = new(big.Int).SetInt64(0)
	t[id].Sub(r, cx)
	t[id].Mod(t[id], N)

	return &RingSign{hsx, hsy, c, t}, nil
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(R *PublicKeyRing, m []byte, rs *RingSign) bool {
	s := R.Len()
	if s == 0 {
		return false
	}
	c := R.Ring[0].Curve
	N := c.Params().N
	x := rs.Hsx
	y := rs.Hsy

	if x.Sign() == 0 || y.Sign() == 0 {
		return false
	}
	if x.Cmp(N) >= 0 || y.Cmp(N) >= 0 {
		return false
	}
	// 1. Tau is on curve
	if !c.IsOnCurve(x, y) {
		return false
	}
	mR := append(m, R.Bytes()...)
	hx, hy := hashG(c, mR)

	sum := new(big.Int).SetInt64(0)
	ax := make([]*big.Int, s, s)
	ay := make([]*big.Int, s, s)
	bx := make([]*big.Int, s, s)
	by := make([]*big.Int, s, s)
	for j := 0; j < s; j++ {
		// 2. Check that cj,tj is in range [0..N]
		if rs.C[j].Cmp(N) >= 0 || rs.T[j].Cmp(N) >= 0 {
			return false
		}
		tb := rs.T[j].Bytes()
		cb := rs.C[j].Bytes()
		ax1, ay1 := c.ScalarBaseMult(tb) // g^tj
		ax2, ay2 := c.ScalarMult(R.Ring[j].X, R.Ring[j].Y, cb) // yj^cj
		ax[j], ay[j] = c.Add(ax1, ay1, ax2, ay2)
		bx1, by1 := c.ScalarMult(hx, hy, tb) // H(mR)^tj
		bx2, by2 := c.ScalarMult(x, y, cb) // tau^cj
		bx[j], by[j] = c.Add(bx1, by1, bx2, by2)
		sum.Add(sum, rs.C[j])
	}
	// 3. Check signature...
	mRab := make([]byte, 0)
	mRab = append(mRab, mR...)
	for i := 0; i < s; i++ {
		mRab = append(mRab, ax[i].Bytes()...)
		mRab = append(mRab, ay[i].Bytes()...)
		mRab = append(mRab, bx[i].Bytes()...)
		mRab = append(mRab, by[i].Bytes()...)
	}
	hashmRab := new(big.Int).SetBytes(hashq(mRab))
	hashmRab.Mod(hashmRab, N)
	sum.Mod(sum, N)
	return sum.Cmp(hashmRab) == 0
}
