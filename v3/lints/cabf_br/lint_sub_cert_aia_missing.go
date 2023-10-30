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

type subCertAiaMissing struct{}

/**************************************************************************************************
BRs: 7.1.2.3c
Code signing and Timestamp Certificate
authorityInformationAccess
This extension MUST be present. It MUST NOT be marked critical.
It MUST contain the HTTP URL of the Issuing CA’s certificate (accessMethod =
1.3.6.1.5.5.7.48.2). If the CA provides OCSP responses, it MUST contain the HTTP URL of the
Issuing CA’s OCSP responder (accessMethod = 1.3.6.1.5.5.7.48.1).
***************************************************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_aia_missing",
		Description:   "Code signing and Timestamp Certificate: This extension MUST be present. It MUST NOT be marked critical.",
		Citation:      "BRs: 7.1.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewSubCertAiaMissing,
	})
}

func NewSubCertAiaMissing() lint.LintInterface {
	return &subCertAiaMissing{}
}

func (l *subCertAiaMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertAiaMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.AiaOID) {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
