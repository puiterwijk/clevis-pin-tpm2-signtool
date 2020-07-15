package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/puiterwijk/clevis-pin-tpm2-signtool/signtool"
	"github.com/puiterwijk/tpm2-policy-simulator/simulator"
)

const (
	publicKeyLocation  = "publickey.json"
	privateKeyLocation = "privatekey.pem"
)

func pcrSelToSignedPolicyStepPCRs(sel *simulator.PcrSelection) (*signtool.SignedPolicyStepPCRs, error) {
	algs := sel.GetHashAlgos()
	if len(algs) != 1 {
		return nil, fmt.Errorf("Invalid number of PCR hash algos selected")
	}
	alg := algs[0]
	algtype := alg.ToCryptoHash()
	if algtype != crypto.SHA256 {
		return nil, fmt.Errorf("Unsupported hash algo used for PCR selection")
	}
	digest, err := sel.GetDigest()
	if err != nil {
		return nil, err
	}
	hasher := algtype.New()
	_, err = hasher.Write(digest)
	if err != nil {
		return nil, err
	}
	digest = hasher.Sum(nil)
	return &signtool.SignedPolicyStepPCRs{
		PcrIds:        sel.GetPcrIDs(alg),
		HashAlgorithm: "SHA256",
		Value:         digest,
	}, nil
}

type signedPolicyStep struct {
	Pcrs *signtool.SignedPolicyStepPCRs `json:"PCRs,omitempty"`
}

type signedPolicy struct {
	PolicyRef []byte             `json:"policy_ref"`
	Steps     []signedPolicyStep `json:"steps"`
	Signature []byte             `json:"signature"`
}

type signedPolicyList []signedPolicy

func createNewKey() (*rsa.PrivateKey, error) {
	fmt.Println("No private key found, generating a new one")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubkey := signtool.PublicKey{
		Rsa: signtool.PublicKeyRSA{
			Scheme:      "RSASSA",
			HashingAlgo: "SHA256",
			Exponent:    key.E,
			Modulus:     key.N.Bytes(),
		},
	}
	pubkeyJSON, err := json.Marshal(pubkey)
	if err != nil {
		return nil, err
	}

	privDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	privPemBlock := pem.Block{
		Bytes: privDer,
		Type:  "PRIVATE KEY",
	}
	privPem := pem.EncodeToMemory(&privPemBlock)

	// Now write both representations
	err = ioutil.WriteFile(privateKeyLocation, privPem, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(publicKeyLocation, pubkeyJSON, 0644)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func getKey() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(privateKeyLocation)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if err != nil {
		return createNewKey()
	}
	privPem, _ := pem.Decode(priv)
	if privPem.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("Private key is of invalid type")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
		return nil, fmt.Errorf("Unable to parse RSA private key")
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Error parsing private key")
	}

	return privateKey, nil
}

func createPolicy() (signedPolicyStep, []byte) {
	pcr0, err := hex.DecodeString("0E6B3C126514CF40E0D10AF7032910DF16F2C2152E5043D7662A8CFB5FA8692D")
	if err != nil {
		panic(err)
	}
	pcr1, err := hex.DecodeString("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7968")
	if err != nil {
		panic(err)
	}

	sel := simulator.NewPcrSelection()
	sel.AddSelection(crypto.SHA256, 0, pcr0)
	sel.AddSelection(crypto.SHA256, 1, pcr1)

	step, err := pcrSelToSignedPolicyStepPCRs(sel)
	if err != nil {
		panic(err)
	}

	sim, err := simulator.NewSimulator(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	err = sim.PolicyPCR(sel)
	if err != nil {
		panic(err)
	}

	return signedPolicyStep{
		Pcrs: step,
	}, sim.GetDigest()
}

func main() {
	privkey, err := getKey()
	if err != nil {
		panic(fmt.Sprintf("Error getting private key: %s", err))
	}

	policyRef := make([]byte, 0)

	step, policyDigest := createPolicy()

	ahash := append(policyDigest, policyRef...)
	ahashSummer := crypto.SHA256.New()
	_, err = ahashSummer.Write(ahash)
	if err != nil {
		panic(err)
	}
	ahash = ahashSummer.Sum(nil)

	signature, err := rsa.SignPKCS1v15(nil, privkey, crypto.SHA256, ahash)
	if err != nil {
		panic(err)
	}

	plist := signedPolicyList{
		signedPolicy{
			PolicyRef: []byte(""),
			Signature: signature,
			Steps: []signedPolicyStep{
				step,
			},
		},
	}

	pListEnc, err := json.Marshal(plist)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("testpolicy.json", pListEnc, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signed policy list written")
}
