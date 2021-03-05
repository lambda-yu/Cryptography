package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func main() {
	msg := "hello word"
	key, _ := NewSigningKey()

	signature, err := Sign([]byte(msg), key)
	if err != nil {
		fmt.Println(err)
	}
	// real signature
	fmt.Println(Verify([]byte(msg), signature, &key.PublicKey))

	// wrong signature
	e_signature := signature[:]
	e_signature[0] = 1
	fmt.Println(Verify([]byte(msg), e_signature, &key.PublicKey))
}

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

func Sign(data []byte, private *ecdsa.PrivateKey) ([]byte, error){
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
	if err != nil {
		return nil, err
	}

	curvesize := private.Curve.Params().P.BitLen() / 8
	signature := make([]byte, curvesize*2)
	rbytes, sbytes := r.Bytes(), s.Bytes()
	copy(signature[:len(rbytes)], rbytes)
	copy(signature[len(rbytes):], sbytes)
	return signature, nil

}
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool{
	digest := sha256.Sum256(data)
	curesize := pubkey.Curve.Params().P.BitLen() / 8
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curesize])
	s.SetBytes(signature[curesize:])
	return ecdsa.Verify(pubkey, digest[:], r, s)
}