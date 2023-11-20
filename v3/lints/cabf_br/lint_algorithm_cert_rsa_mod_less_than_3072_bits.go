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

type CertRsaParsedTestsKeySize struct{}

/*
6.1.5.2 Code signing Certificate and Timestamp Authority key sizes
For Keys corresponding to Subscriber code signing and Timestamp Authority Certificates:
  - If the Key is RSA, then the modulus MUST be at least 3072 bits in length.
  - If the Key is ECDSA, then the curve MUST be one of NIST P‐256, P‐384, or P‐521.
  - If the Key is DSA, then one of the following key parameter options MUST be used:
  - Key length (L) of 2048 bits and modulus length (N) of 224 bits
  - Key length (L) of 2048 bits and modulus length (N) of 256 bits
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_cert_rsa_mod_less_than_3072_bits",
		Description:   "If the Key is RSA, then the modulus MUST be at least 3072 bits in length.",
		Citation:      "CSBRs: 6.1.5",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.RSA3072Date,
		Lint:          NewCertRsaParsedTestsKeySize,
	})
}

func NewCertRsaParsedTestsKeySize() lint.LintInterface {
	return &CertRsaParsedTestsKeySize{}
}

func (l *CertRsaParsedTestsKeySize) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA && util.IsSubscriberCert(c)
}

func (l *CertRsaParsedTestsKeySize) Execute(c *x509.Certificate) *lint.LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if key.N.BitLen() < 3072 {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
