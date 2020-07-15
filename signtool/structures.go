package signtool

type PublicKeyRSA struct {
	Scheme      string `json:"scheme"`
	HashingAlgo string `json:"hashing_algo"`
	Exponent    int    `json:"exponent"`
	Modulus     []byte `json:"modulus"`
}

type PublicKey struct {
	Rsa PublicKeyRSA `json:"RSA"`
}

type SignedPolicyStepPCRs struct {
	PcrIds        []int  `json:"pcr_ids"`
	HashAlgorithm string `json:"hash_algorithm"`
	Value         []byte `json:"value"`
}
