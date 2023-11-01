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

type subCertKeyUsageMissing struct{}

/************************************************
RFC 5280: 4.2.1.3
Conforming CAs MUST include this extension in certificates that
   contain public keys that are used to validate digital signatures on
   other public key certificates or CRLs.  When present, conforming CAs
   SHOULD mark this extension as critical.

7.1.2.2
e. keyUsage
This extension MUST be present and MUST be marked critical.
The bit position for digitalSignature MUST be set. Bit positions for keyCertSign and
cRLSign MUST NOT be set. All other bit positions SHOULD NOT be set.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_key_usage_missing",
		Description:   "This extension MUST be present and MUST be marked critical.",
		Citation:      "BRs: 7.1.2.3e, RFC 5280: 4.2.1.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.RFC3280Date,
		Lint:          NewSubCertKeyUsageMissing,
	})
}

func NewSubCertKeyUsageMissing() lint.LintInterface {
	return &subCertKeyUsageMissing{}
}

func (l *subCertKeyUsageMissing) CheckApplies(c *x509.Certificate) bool {
	// fmt.Print("text")
	return util.IsSubscriberCert(c)
}

func (l *subCertKeyUsageMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage != x509.KeyUsage(0) {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
