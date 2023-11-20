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

type subCaAuthorityKeyIdCritical struct{}

/***********************************************************************
7.1.2.2h
Subordinate CA Certificate
authorityKeyIdentifier
This extension MUST be present and MUST NOT be marked critical.
***********************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_ca_akid_missing",
		Description:   "This extension MUST be present and MUST NOT be marked critical.",
		Citation:      "CSBRs: 7.1.2.2 & RFC 5280: 4.2.1.1",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.RFC2459Date,
		Lint:          NewSubCaAuthorityKeyIdCritical,
	})
}

func NewSubCaAuthorityKeyIdCritical() lint.LintInterface {
	return &subCaAuthorityKeyIdCritical{}
}

func (l *subCaAuthorityKeyIdCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c)
}

func (l *subCaAuthorityKeyIdCritical) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.AuthkeyOID) {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{Status: lint.Error}

}
