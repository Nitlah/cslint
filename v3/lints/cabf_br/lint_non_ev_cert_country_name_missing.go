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

type nonEVCertCountryNameMissing struct{}

/************************************************
BRs: 7.1.2.1e
The	Certificate	Subject	MUST contain the following:
‐	countryName	(OID 2.5.4.6).
This field MUST	contain	the	two‐letter	ISO	3166‐1 country code	for	the country
in which the CA’s place	of business	is located.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_non_ev_cert_country_name_missing",
		Description: "The subject:countryName MUST contain the two‐letter ISO 3166‐1 country" +
			"code associated with the location of the Subject verified under BR Section 3.2.2.3",
		Citation:      "BRs: 7.1.4.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewNonEVCertCountryNameMissing,
	})
}

func NewNonEVCertCountryNameMissing() lint.LintInterface {
	return &nonEVCertCountryNameMissing{}
}

func (l *nonEVCertCountryNameMissing) CheckApplies(c *x509.Certificate) bool {
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

func (l *nonEVCertCountryNameMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.Country != nil && c.Subject.Country[0] != "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
