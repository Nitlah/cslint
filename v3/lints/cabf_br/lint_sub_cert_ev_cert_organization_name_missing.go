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

type evOrgMissing struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ev_organization_name_missing",
		Description:   "EV certificates must include organizationName in subject",
		Citation:      "CSBRs: 7.1.4.2.4",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.ZeroDate,
		Lint:          NewEvOrgMissing,
	})
}

func NewEvOrgMissing() lint.LintInterface {
	return &evOrgMissing{}
}

func (l *evOrgMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *evOrgMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.Organization != nil && c.Subject.Organization[0] != "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
