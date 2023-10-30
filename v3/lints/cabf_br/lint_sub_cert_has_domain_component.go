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

type certDomainComponent struct{}

/*
7.1.4.2.2 Subject distinguished name fields ‑ EV and Non‑EV Code Signing Certificates
c. Certificate Field: subject:domainComponent (OID 0.9.2342.19200300.100.1.25)

	Required/Optional: Prohibited
	Contents: This field MUST not be present in a Code Signing Certificate.
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_cert_has_domain_component",
		Description:   "domainComponent：This field MUST not be present in a Code Signing Certificate.",
		Citation:      "7.1.4.2.2",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewCertDomainComponent,
	})
}

func NewCertDomainComponent() lint.LintInterface {
	return &certDomainComponent{}
}

func (l *certDomainComponent) CheckApplies(c *x509.Certificate) bool {
	ekuFields := false
	if c.ExtKeyUsage != nil {
		for _, v := range c.ExtKeyUsage {
			if v == x509.ExtKeyUsageCodeSigning {
				ekuFields = true
				break
			}
		}
	}
	return ekuFields && util.IsSubscriberCert(c)
}

func (l *certDomainComponent) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.DomainComponent != nil {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
