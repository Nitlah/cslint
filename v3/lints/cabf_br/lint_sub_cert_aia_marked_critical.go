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

type subCertAiaMarkedCritical struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_aia_marked_critical",
		Description:   "Subscriber Certificate: authorityInformationAccess MUST NOT be marked critical",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubCertAiaMarkedCritical,
	})
}

func NewSubCertAiaMarkedCritical() lint.LintInterface {
	return &subCertAiaMarkedCritical{}
}

func (l *subCertAiaMarkedCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.AiaOID)
}

func (l *subCertAiaMarkedCritical) Execute(c *x509.Certificate) *lint.LintResult {
	e := util.GetExtFromCert(c, util.AiaOID)
	if e.Critical {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
