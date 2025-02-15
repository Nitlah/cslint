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

type caAiaShouldNotBeMissing struct{}

/***********************************************
CAB BR 1.7.1 Section 7.1.2.2c - authorityInformationAccess
This extension SHOULD be present. It MUST NOT be marked critical.
It SHOULD contain the HTTP URL of the Issuing CA’s certificate (accessMethod =
1.3.6.1.5.5.7.48.2). It MAY contain the HTTP URL of the Issuing CA’s OCSP responder
(accessMethod = 1.3.6.1.5.5.7.48.1).
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_ca_aia_missing",
		Description:   "Subordinate CA Certificate: authorityInformationAccess MUST be present.",
		Citation:      "CSBRs: 7.1.2.2",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewCaAiaShouldNotBeMissing,
	})
}

func NewCaAiaShouldNotBeMissing() lint.LintInterface {
	return &caAiaShouldNotBeMissing{}
}

func (l *caAiaShouldNotBeMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c)
}

func (l *caAiaShouldNotBeMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.AiaOID) {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
