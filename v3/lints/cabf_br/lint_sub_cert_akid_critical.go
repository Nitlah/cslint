package cabr_br

import (
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

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
)

type subCertAuthorityKeyIdCritical struct{}

/***********************************************************************
7.1.2.3 Code signing and Timestamp Certificate
g. authorityKeyIdentifier
This extension MUST be present and MUST NOT be marked critical.

***********************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_akid_critical",
		Description:   "This extension MUST be present and MUST NOT be marked critical.",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBRV30DATE,
		Lint:          NewSubCertAuthorityKeyIdCritical,
	})
}

func NewSubCertAuthorityKeyIdCritical() lint.LintInterface {
	return &subCertAuthorityKeyIdCritical{}
}

func (l *subCertAuthorityKeyIdCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.AuthkeyOID)
}

func (l *subCertAuthorityKeyIdCritical) Execute(c *x509.Certificate) *lint.LintResult {
	authkeyOID := util.GetExtFromCert(c, util.AuthkeyOID)
	if authkeyOID.Critical {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}

}
