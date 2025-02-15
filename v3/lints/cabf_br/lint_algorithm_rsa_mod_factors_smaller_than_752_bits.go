package cabr_br

/*
 * ZLint Copyright 2023 Regents of the University of Michigan
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

type rsaModSmallFactor struct{}

/**************************************************************************************************
6.1.6. Public Key Parameters Generation and Quality Checking
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent SHOULD be in the range between 2^16+1 and 2^256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Citation: Section 5.3.3, NIST SP 800‐89].
**************************************************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "w_rsa_mod_factors_smaller_than_752",
		Description:   "RSA: Modulus SHOULD also have the following characteristics: no factors smaller than 752",
		Citation:      "CSBRs: 6.1.6",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CABV113Date,
		Lint:          NewRsaModSmallFactor,
	})
}

func NewRsaModSmallFactor() lint.LintInterface {
	return &rsaModSmallFactor{}
}

func (l *rsaModSmallFactor) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA
}

func (l *rsaModSmallFactor) Execute(c *x509.Certificate) *lint.LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if util.PrimeNoSmallerThan752(key.N) {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{Status: lint.Warn}

}
