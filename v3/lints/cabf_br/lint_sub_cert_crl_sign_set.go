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

type subCertCRLSignSet struct{}

/************************************************
BRs: 7.1.2.1b
This extension MUST be present and MUST be marked critical. Bit positions for
keyCertSign and cRLSign MUST be set. If the Root CA Private Key is used for
signing OCSP responses, then the digitalSignature bit MUST be set.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_crl_sign_set",
		Description:   "Bit positions for keyCertSign and cRLSign MUST NOT be set.",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubCertCRLSignSet,
	})
}

func NewSubCertCRLSignSet() lint.LintInterface {
	return &subCertCRLSignSet{}
}

func (l *subCertCRLSignSet) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && util.IsExtInCert(c, util.KeyUsageOID)
}

func (l *subCertCRLSignSet) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
