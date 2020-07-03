package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	publicKeyLocation  = "publickey.json"
	privateKeyLocation = "privatekey.pem"
)

type publicKeyRSA struct {
	Scheme      string `json:"scheme"`
	HashingAlgo string `json:"hashing_algo"`
	Exponent    int    `json:"exponent"`
	Modulus     string `json:"modulus"`
}

type publicKey struct {
	Rsa publicKeyRSA `json:"RSA"`
}

func createNewKey() (*rsa.PrivateKey, error) {
	fmt.Println("No private key found, generating a new one")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubmod := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	pubkey := publicKey{
		Rsa: publicKeyRSA{
			Scheme:      "RSASSA",
			HashingAlgo: "SHA256",
			Exponent:    key.E,
			Modulus:     pubmod,
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

func main() {
	privkey, err := getKey()
	if err != nil {
		panic(fmt.Sprintf("Error getting private key: %s", err))
	}
	fmt.Println("Private key: ", privkey)
}
