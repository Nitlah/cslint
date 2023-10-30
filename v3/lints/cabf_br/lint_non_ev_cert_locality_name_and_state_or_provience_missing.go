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

type nonEVCertLocalityNameMissing struct{}

/************************************************
7.1.4.2.3 Subject distinguished name field ‑ Non‑EV Code Signing Certificates
c. Certificate Field: subject:localityName (OID: 2.5.4.7)
	Required/Optional: Required if the subject:stateOrProvinceName field is absent.
	Optional if the subject:stateOrProvinceName field is present.
	Contents: If present, the subject:localityName field MUST contain the Subject’s locality
		information as verified under BR Section 3.2. If the subject:countryName field specifies
		the ISO 3166‐1 user‐assigned code of XX in accordance with BR Section 7.1.4.2.2.h., the
		subject:localityName field MAY contain the Subject’s locality and/or state or province
		information as verified under BR Section 3.2.2.1 or 3.2.3.
d. Certificate Field: subject:stateOrProvinceName (OID: 2.5.4.8)
	Required/Optional: Required if the subject:localityName field is absent. Optional if the
	subject:localityName field is present.
	Contents: If present, the subject:stateOrProvinceName field MUST contain the
		Subject’s state or province information as verified under BR Section 3.2.2.1 or 3.2.3. If the
		subject:countryName field specifies the ISO 3166‐1 user‐assigned code of XX in
		accordance with BR Section 7.1.4.2.2.h., the subject:stateOrProvinceName field MAY
		contain the full name of the Subject’s country information as verified under BR Section
		3.2.2.1 or 3.2.3.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_non_ev_cert_locality_name_and_state_or_provience_missing",
		Description: "Certificate Field: subject:localityName (OID: 2.5.4.7) " +
			"Required/Optional: Required if the subject:stateOrProvinceName field is absent",
		Citation:      "BRs: 7.1.4.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewNonEVCertLocalityNameMissing,
	})
}

func NewNonEVCertLocalityNameMissing() lint.LintInterface {
	return &nonEVCertLocalityNameMissing{}
}

func (l *nonEVCertLocalityNameMissing) CheckApplies(c *x509.Certificate) bool {
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

func (l *nonEVCertLocalityNameMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.CABFOrganizationIdentifier == nil || (c.CABFOrganizationIdentifier.State == "" && c.Subject.Locality == nil) {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
