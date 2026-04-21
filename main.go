package main

import (
	"log"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func main() {
	// go-crypto
	// OLD signature
	signaturePath := "./terraform_1.0.0_SHA256SUMS.sig"
	artifactPath := "./terraform_1.0.0_SHA256SUMS"
	// verify with OLD key
	gcResult, err := verifyWithGoCrypto(signaturePath, artifactPath, oldRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("go-crypto: signature %q valid for %q, signed with OLD key (%s)",
		signaturePath, artifactPath, gcResult.PrimaryKey.KeyIdString())
	// verify with NEW key
	gcResult, err = verifyWithGoCrypto(signaturePath, artifactPath, newRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("go-crypto: signature %q valid for %q, signed with NEW key (%s)",
		signaturePath, artifactPath, gcResult.PrimaryKey.KeyIdString())

	// NEW signature
	signaturePath = "./terraform_1.14.9_SHA256SUMS.sig"
	artifactPath = "./terraform_1.14.9_SHA256SUMS"
	// verify with OLD key
	gcResult, err = verifyWithGoCrypto(signaturePath, artifactPath, oldRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("go-crypto: signature %q valid for %q, signed with OLD key (%s)",
		signaturePath, artifactPath, gcResult.PrimaryKey.KeyIdString())
	// verify with NEW key
	gcResult, err = verifyWithGoCrypto(signaturePath, artifactPath, newRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("go-crypto: signature %q valid for %q, signed with NEW key (%s)",
		signaturePath, artifactPath, gcResult.PrimaryKey.KeyIdString())

	// gopenpgp
	// OLD signature
	signaturePath = "./terraform_1.0.0_SHA256SUMS.sig"
	artifactPath = "./terraform_1.0.0_SHA256SUMS"
	// verify with OLD key
	result, err := verifyWithGopenPGP(signaturePath, artifactPath, oldRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gopenpgp: signature %q valid for %q, signed with OLD key (%s)",
		signaturePath, artifactPath, result.SignedByKeyIdHex())
	// verify with NEW key
	result, err = verifyWithGopenPGP(signaturePath, artifactPath, newRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gopenpgp: signature %q valid for %q, signed with NEW key (%s)",
		signaturePath, artifactPath, result.SignedByKeyIdHex())

	// NEW signature
	signaturePath = "./terraform_1.14.9_SHA256SUMS.sig"
	artifactPath = "./terraform_1.14.9_SHA256SUMS"
	// verify with OLD key
	result, err = verifyWithGopenPGP(signaturePath, artifactPath, oldRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gopenpgp: signature %q valid for %q, signed with OLD key (%s)",
		signaturePath, artifactPath, result.SignedByKeyIdHex())
	// verify with NEW key
	result, err = verifyWithGopenPGP(signaturePath, artifactPath, newRawKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gopenpgp: signature %q valid for %q, signed with NEW key (%s)",
		signaturePath, artifactPath, result.SignedByKeyIdHex())
}

func verifyWithGoCrypto(signaturePath, artifactPath, rawKey string) (*openpgp.Entity, error) {
	keyReader := strings.NewReader(rawKey)
	artifactReader, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	signatureReader, err := os.Open(signaturePath)
	if err != nil {
		return nil, err
	}

	keyRing, err := openpgp.ReadArmoredKeyRing(keyReader)
	if err != nil {
		return nil, err
	}
	signer, err := openpgp.CheckDetachedSignature(keyRing, artifactReader, signatureReader, nil)
	if err == errors.ErrKeyExpired {
		// ignore key expiration
		err = nil
	}
	return signer, err
}

func verifyWithGopenPGP(signaturePath, artifactPath, rawKey string) (*crypto.VerifyResult, error) {
	key, err := crypto.NewKeyFromArmored(rawKey)
	if err != nil {
		return nil, err
	}
	verifyBuilder := crypto.PGP().Verify().VerificationKey(key)
	signingKey, err := verifyBuilder.New()
	if err != nil {
		return nil, err
	}

	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, err
	}

	signatureBytes, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, err
	}

	return signingKey.VerifyDetached(artifactBytes, signatureBytes, crypto.Auto)
}
