package legacy

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

type subCaHasTsAndCsEKUs struct{}

/*
7.1.2.2
f. extKeyUsage

If the Subordinate CA will be used to issue Code Signing Certificates:
  - id-kp-codeSigning MUST be present.
  - id-kp-timeStamping MUST NOT be present.

If the Subordinate CA will be used to issue Timestamp Certificates:
  - id-kp-timeStamping MUST be present.
  - id-kp-codeSigning MUST NOT be present
*/

//func init() {
//	lint.RegisterLint(&lint.Lint{
//		Name: "e_ca_eku_has_code_signing_and_time_stamping",
//		Description: "If the Subordinate CA will be used to issue Code Signing Certificates:" +
//			"• id-kp-codeSigning MUST be present." +
//			"• id-kp-timeStamping MUST NOT be present." +
//			"If the Subordinate CA will be used to issue Timestamp Certificates:" +
//			"• id-kp-timeStamping MUST be present." +
//			"• id-kp-codeSigning MUST NOT be present",
//		Citation:      "CSBRs: 7.1.2.3",
//		Source:        lint.CSBaselineRequirements,
//		EffectiveDate: util.CSBREffectiveDate,
//		Lint:          NewSubCaHasTsAndCsEKUs,
//	})
//}

func NewSubCaHasTsAndCsEKUs() lint.LintInterface {
	return &subCaHasTsAndCsEKUs{}
}

func (l *subCaHasTsAndCsEKUs) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c)
}

func (l *subCaHasTsAndCsEKUs) Execute(c *x509.Certificate) *lint.LintResult {
	codeSigningParent := false
	timeStampingParent := false
	for _, v := range c.ExtKeyUsage {
		if v == x509.ExtKeyUsageCodeSigning {
			codeSigningParent = true
		} else if v == x509.ExtKeyUsageTimeStamping {
			timeStampingParent = true
		}
	}
	if codeSigningParent && timeStampingParent {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
