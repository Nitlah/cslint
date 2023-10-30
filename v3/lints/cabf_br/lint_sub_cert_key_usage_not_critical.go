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

type subCertKeyUsageNotCrit struct{}

/************************************************
BRs: 7.1.2.3
e. keyUsage
This extension MUST be present and MUST be marked critical.
The bit position for digitalSignature MUST be set. Bit positions for keyCertSign and
cRLSign MUST NOT be set. All other bit positions SHOULD NOT be set
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_key_usage_not_critical",
		Description:   "This extension MUST be present and MUST be marked critical.",
		Citation:      "BRs: 7.1.2.1",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewSubCertKeyUsageNotCrit,
	})
}

func NewSubCertKeyUsageNotCrit() lint.LintInterface {
	return &subCertKeyUsageNotCrit{}
}

func (l *subCertKeyUsageNotCrit) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.KeyUsageOID)
}

func (l *subCertKeyUsageNotCrit) Execute(c *x509.Certificate) *lint.LintResult {
	if e := util.GetExtFromCert(c, util.KeyUsageOID); e.Critical {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
