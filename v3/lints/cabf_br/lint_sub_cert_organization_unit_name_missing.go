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
7.1.4.2.2 Subject distinguished name fields ‑ EV and Non‑EV Code Signing Certificates
b. 	Certificate Field: subject:organizationalUnitName (OID 2.5.4.11)

	Required/Optional: Optional
	Contents: The CA MUST implement a process that prevents an OU attribute from including a
		name, DBA, tradename, trademark, address, location, or other text that refers to a specific
		natural person or Legal Entity unless the CA has verified this information in accordance with
		Section 3.2
*/
type certOrganizationUnitNameMissing struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "n_sub_cert_organization_unit_name_missing",
		Description:   "Required/Optional: Optional",
		Citation:      "BRs: 7.1.4.3.1",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewCertOrganizationUnitNameMissing,
	})
}

func NewCertOrganizationUnitNameMissing() lint.LintInterface {
	return &certOrganizationUnitNameMissing{}
}

func (l *certOrganizationUnitNameMissing) CheckApplies(c *x509.Certificate) bool {
	codeSigningParent := false
	for _, v := range c.ExtKeyUsage {
		if v == x509.ExtKeyUsageCodeSigning {
			codeSigningParent = true
			break
		}
	}
	return util.IsSubscriberCert(c) && codeSigningParent
}

func (l *certOrganizationUnitNameMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.OrganizationalUnit != nil && c.Subject.OrganizationalUnit[0] == "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Notice}
	}
}
