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
