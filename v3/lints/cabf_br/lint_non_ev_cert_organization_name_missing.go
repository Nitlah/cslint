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

type certOrganizationNameMissing struct{}

/*
7.1.4.2.3 Subject distinguished name field ‑ Non‑EV Code Signing Certificates
a. Certificate Field: subject:organizationName (OID 2.5.4.10)

	Required/Optional: Required
	Contents: The subject:organizationName field MUST contain either the Subject’s name
		or DBA as verified under BR Section 3.2. The CA MAY include information in this field that
		differs slightly from the verified name, such as common variations or abbreviations,
		provided that the CA documents the difference and any abbreviations used are locally
		accepted abbreviations; e.g., if the official record shows “Company Name Incorporated”, the
		CA MAY use “Company Name Inc.” or “Company Name”. Because subject name attributes for
		individuals (e.g. subject:givenName (2.5.4.42) and subject:surname (2.5.4.4)) are not
		broadly supported by application software, the CA MAY use the
		subject:organizationName field to convey a natural person Subject’s name or DBA. The
		CA MUST have a documented process for verifying that the information included in the
		subject:organizationName field is not misleading to a Relying Party.
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_organization_name_missing",
		Description:   "The subject:organizationName field MUST contain either the Subject’s name\nor DBA as verified under BR Section 3.2.",
		Citation:      "BRs: 7.1.4.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewCertOrganizationNameMissing,
	})
}

func NewCertOrganizationNameMissing() lint.LintInterface {
	return &certOrganizationNameMissing{}
}

func (l *certOrganizationNameMissing) CheckApplies(c *x509.Certificate) bool {
	codeSigningParent := false
	if c.ExtKeyUsage != nil {
		for _, v := range c.ExtKeyUsage {
			if v == x509.ExtKeyUsageCodeSigning {
				codeSigningParent = true
				break
			}
		}
	}
	return util.IsSubscriberCert(c) && codeSigningParent && !util.IsEV(c.PolicyIdentifiers)
}

func (l *certOrganizationNameMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.Organization != nil && c.Subject.Organization[0] != "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
