// Copyright 2020 Patrick Uiterwijk
//
// Licensed under the EUPL-1.2-or-later
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	"gopkg.in/yaml.v2"

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
		PcrValues:     sel.GetValues(alg),
	}, nil
}

type policyRequestStepPCRSelection struct {
	PcrID int    `yaml:"pcr_id"`
	Value string `yaml:"value"`
}

type policyRequestStepPCR struct {
	HashAlgorithm string                          `yaml:"hash_algorithm"`
	Selection     []policyRequestStepPCRSelection `yaml:"selection"`
}

type policyRequestStep struct {
	Pcrs *policyRequestStepPCR `yaml:"PCRs,omitempty"`
}

type policyRequest struct {
	PolicyRef string              `yaml:"policy_ref"`
	Steps     []policyRequestStep `yaml:"steps"`
}

type policyRequestList []policyRequest

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
	fmt.Fprintln(os.Stderr, "No private key found, generating a new one")

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

func playStep(step policyRequestStep, sim *simulator.Tpm2PolicySimulator) (*signedPolicyStep, error) {
	if step.Pcrs != nil {
		sel := simulator.NewPcrSelection()
		for _, pcrsel := range step.Pcrs.Selection {
			pcrval, err := hex.DecodeString(pcrsel.Value)
			if err != nil {
				return nil, fmt.Errorf("Error decoding PCR value hex: %s", err)
			}
			sel.AddSelection(crypto.SHA256, pcrsel.PcrID, pcrval)
		}

		step, err := pcrSelToSignedPolicyStepPCRs(sel)
		if err != nil {
			return nil, err
		}
		err = sim.PolicyPCR(sel)
		if err != nil {
			return nil, err
		}

		return &signedPolicyStep{
			Pcrs: step,
		}, nil
	}

	return nil, fmt.Errorf("Unrecognized policy step")
}

func playSteps(steps []policyRequestStep) ([]signedPolicyStep, []byte, error) {
	outsteps := make([]signedPolicyStep, len(steps))

	sim, err := simulator.NewSimulator(crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}

	for i, step := range steps {
		sigstep, err := playStep(step, sim)
		if err != nil {
			return nil, nil, err
		}
		outsteps[i] = *sigstep
	}
	return outsteps, sim.GetDigest(), nil
}

func signPolicy(privkey *rsa.PrivateKey, request policyRequest) (*signedPolicy, error) {
	sigpol := new(signedPolicy)
	sigpol.PolicyRef = []byte(request.PolicyRef)

	steps, policyDigest, err := playSteps(request.Steps)
	if err != nil {
		return nil, err
	}
	sigpol.Steps = steps

	ahash := append(policyDigest, sigpol.PolicyRef...)
	ahashSummer := crypto.SHA256.New()
	_, err = ahashSummer.Write(ahash)
	if err != nil {
		return nil, err
	}
	ahash = ahashSummer.Sum(nil)

	signature, err := rsa.SignPKCS1v15(nil, privkey, crypto.SHA256, ahash)
	if err != nil {
		return nil, err
	}

	sigpol.Signature = signature
	return sigpol, nil
}

func main() {
	privkey, err := getKey()
	if err != nil {
		panic(fmt.Sprintf("Error getting private key: %s", err))
	}

	policyIn, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	var policy policyRequestList
	err = yaml.Unmarshal(policyIn, &policy)
	if err != nil {
		panic(err)
	}

	signedPolicies := make([]signedPolicy, len(policy))

	for i, polreq := range policy {
		sigpol, err := signPolicy(privkey, polreq)
		if err != nil {
			panic(err)
		}
		signedPolicies[i] = *sigpol
	}

	pListEnc, err := json.Marshal(signedPolicies)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(pListEnc))
}
