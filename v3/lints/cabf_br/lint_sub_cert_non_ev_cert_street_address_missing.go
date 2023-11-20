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

type nonEVCertStreetAddressMissing struct{}

/*
b. Certificate Field: subject:streetAddress (OID: 2.5.4.9)

	Required/Optional: Optional
	Contents: If present, the subject:streetAddress field MUST contain the Subject’s street
		address information as verified under BR Section 3.2.2.1 or 3.2.3.
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "n_non_EV_cert_street_address_missing",
		Description:   "Required/Optional: Optional",
		Citation:      "CSBRs: 7.1.4.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewnonEVCertStreetAddressMissing,
	})
}

func NewnonEVCertStreetAddressMissing() lint.LintInterface {
	return &nonEVCertStreetAddressMissing{}
}

func (l *nonEVCertStreetAddressMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !util.IsEV(c.PolicyIdentifiers)

}

func (l *nonEVCertStreetAddressMissing) Execute(c *x509.Certificate) *lint.LintResult {
	//fmt.Println(c.Subject)
	if c.Subject.StreetAddress != nil && c.Subject.StreetAddress[0] == "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Notice}
	}
}
