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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subCertHasOtherEKUs struct{}

/*
7.1.2.3
f. extKeyUsage

	If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST be present
	and the following EKUs MAY be present:
		• Lifetime Signing OID (1.3.6.1.4.1.311.10.3.13)
		• id-kp-emailProtection
		• Document Signing (1.3.6.1.4.1.311.3.10.3.12)

	If the Certificate is a Timestamp Certificate, then id-kp-timeStamping MUST be present
	and MUST be marked critical.

	Additionally, the following EKUs MUST NOT be present:
		• anyExtendedKeyUsage
		• id-kp-serverAuth

	Other values SHOULD NOT be present. If any other value is present, the CA MUST have a
	business agreement with a Platform vendor requiring that EKU in order to issue a
	Platform‐specific code signing certificate with that EKU.
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "w_cert_eku_has_other_eku",
		Description: "Other values SHOULD NOT be present. If any other value is present, " +
			"the CA MUST have a business agreement with a Platform vendor requiring that EKU in order to " +
			"issue a Platform‐specific code signing certificate with that EKU",
		Citation:      "7.1.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubCertHasOtherEKUs,
	})
}

func NewSubCertHasOtherEKUs() lint.LintInterface {
	return &subCertHasOtherEKUs{}
}

func (l *subCertHasOtherEKUs) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertHasOtherEKUs) Execute(c *x509.Certificate) *lint.LintResult {
	codeSigningEKU := make(map[int]int)
	codeSigningEKU[int(x509.ExtKeyUsageMicrosoftLifetimeSigning)] = 1
	codeSigningEKU[int(x509.ExtKeyUsageCodeSigning)] = 1
	codeSigningEKU[int(x509.ExtKeyUsageEmailProtection)] = 1
	codeSigningEKU[int(x509.ExtKeyUsageMicrosoftDocumentSigning)] = 1
	codeSigningEKU[int(x509.ExtKeyUsageAny)] = 1
	codeSigningEKU[int(x509.ExtKeyUsageServerAuth)] = 1

	for _, v := range c.ExtKeyUsage {
		if _, exists := codeSigningEKU[int(v)]; !exists {
			return &lint.LintResult{Status: lint.Warn}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
