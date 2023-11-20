package cabr_br

/*
 * ZLint Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type CARsaParsedTestsKeySize struct{}

/*
6.1.5.1 Root and Subordinate CA key sizes
For Keys corresponding to Root and Subordinate CAs:
If the Key is RSA, then the modulus MUST be at least 4096 bits in length.
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ca_rsa_mod_less_than_4096_bits",
		Description:   "If the Key is RSA, then the modulus MUST be at least 4096 bits in length.",
		Citation:      "CSBRs: 6.1.5",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.RSA4096Date,
		Lint:          NewCARsaParsedTestsKeySize,
	})
}

func NewCARsaParsedTestsKeySize() lint.LintInterface {
	return &CARsaParsedTestsKeySize{}
}

func (l *CARsaParsedTestsKeySize) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA && util.IsCACert(c)
}

func (l *CARsaParsedTestsKeySize) Execute(c *x509.Certificate) *lint.LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if key.N.BitLen() < 4096 {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
