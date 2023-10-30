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

type nonEVCertPostalCodeMissing struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "n_non_EV_cert_postal_code_missing",
		Description:   "Certificate Field: subject:postalCode (OID: 2.5.4.17) Required/Optional: Optional",
		Citation:      "BRs: 7.1.4.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewNonEVCertPostalCodeMissing,
	})
}

func NewNonEVCertPostalCodeMissing() lint.LintInterface {
	return &nonEVCertPostalCodeMissing{}
}

func (l *nonEVCertPostalCodeMissing) CheckApplies(c *x509.Certificate) bool {
	codeSigningParent := false
	if c.ExtKeyUsage != nil {
		for _, v := range c.ExtKeyUsage {
			if v == x509.ExtKeyUsageCodeSigning {
				codeSigningParent = true
				break
			}
		}
	}
	return codeSigningParent && util.IsSubscriberCert(c) && !util.IsEV(c.PolicyIdentifiers)
}

func (l *nonEVCertPostalCodeMissing) Execute(c *x509.Certificate) *lint.LintResult {
	//fmt.Println(c.Subject)
	if c.Subject.PostalCode != nil && c.Subject.PostalCode[0] == "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Notice}
	}
}
