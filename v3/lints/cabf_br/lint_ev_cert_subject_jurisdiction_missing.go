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

/*
7.1.4.2.4 Subject distinguished name fields ‑ EV Code Signing Certificates
c. 	Certificate Field: Subject Jurisdiction of Incorporation or Registration Fields

	Required/Optional: Required
	Contents: As specified in Section 9.2.4 of the EV Guidelines.

9.2.4. Subject Jurisdiction of Incorporation or Registration Field
Certificate Fields:

	Locality (if required):
	subject:jurisdictionLocalityName (OID: 1.3.6.1.4.1.311.60.2.1.1)
	State or province (if required):
	subject:jurisdictionStateOrProvinceName (OID: 1.3.6.1.4.1.311.60.2.1.2)
	Country:
	subject:jurisdictionCountryName (OID: 1.3.6.1.4.1.311.60.2.1.3)

Required/Optional: Required
Contents: These fields MUST NOT contain information that is not relevant to the level of the

	Incorporating Agency or Registration Agency. For example, the Jurisdiction of Incorporation for
	an Incorporating Agency or Jurisdiction of Registration for a Registration Agency that operates at
	the country level MUST include the country information but MUST NOT include the state or
	province or locality information. Similarly, the jurisdiction for the applicable Incorporating
	Agency or Registration Agency at the state or province level MUST include both country and state
	or province information, but MUST NOT include locality information. And, the jurisdiction for the
	applicable Incorporating Agency or Registration Agency at the locality level MUST include the
	country and state or province information, where the state or province regulates the registration
	of the entities at the locality level, as well as the locality information. Country information MUST
	be specified using the applicable ISO country code. State or province or locality information
	(where applicable) for the Subject’s Jurisdiction of Incorporation or Registration MUST be
	specified using the full name of the applicable jurisdiction.
	Effective as of 1 October 2020, the CA SHALL ensure that, at time of issuance, the values within
	these fields have been disclosed within the latest publicly‐available disclosure, as described in
	Section 11.1.3, as acceptable values for the applicable Incorporating Agency or Registration Agency.
*/
type evNoJurisdiction struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ev_jurisdiction_missing",
		Description:   "EV certificates must include jurisdictionCountryName in subject",
		Citation:      "BRs:7.1.4.2.4",
		Source:        lint.CABFEVGuidelines,
		EffectiveDate: util.ZeroDate,
		Lint:          NewEvNoJurisdiction,
	})
}

func NewEvNoJurisdiction() lint.LintInterface {
	return &evNoJurisdiction{}
}

func (l *evNoJurisdiction) CheckApplies(c *x509.Certificate) bool {
	ekuFields := false
	if c.ExtKeyUsage != nil {
		for _, v := range c.ExtKeyUsage {
			if v == x509.ExtKeyUsageCodeSigning {
				ekuFields = true
				break
			}
		}
	}
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c) && ekuFields
}

func (l *evNoJurisdiction) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.JurisdictionCountry == nil {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
