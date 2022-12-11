package rsa

/*
	Reference: https://medium.com/better-programming/build-an-rsa-asymmetric-cryptography-generator-in-go-d202b18bcfd0
	Do take sometime to read the blog post from the above link, the below package code combines PEM and writeFile functions into one function.
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// generateRSAKeyPair generates RSA key pair which is private and public respectively.
func generateRSAKeyPair(size int) (privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	privKey, _ = rsa.GenerateKey(rand.Reader, size)
	pubKey = &privKey.PublicKey
	return
}

// ExportRSAKeysToFile exports key pairs to files.
func ExportRSAKeysToFile(pubFileName, privFileName string, keySize int) error {

	privKey, pubKey := generateRSAKeyPair(keySize)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	wrPrivKeyFileErr := ioutil.WriteFile(privFileName, privPEMBytes, 0600)
	if wrPrivKeyFileErr != nil {
		return wrPrivKeyFileErr
	}
	pubKeyBytes, pubKeyMarshalErr := x509.MarshalPKIXPublicKey(pubKey)
	if pubKeyMarshalErr != nil {
		return pubKeyMarshalErr
	}
	pubPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)
	wrPubKeyFileErr := ioutil.WriteFile(pubFileName, pubPEMBytes, 0600)
	if wrPubKeyFileErr != nil {
		return wrPubKeyFileErr
	}
	return nil
}
