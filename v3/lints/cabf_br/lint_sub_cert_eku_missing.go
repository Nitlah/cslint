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

type subExtKeyUsage struct{}

/*******************************************************************************************************
BRs: 7.1.2.3
extKeyUsage (required)

If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST be present
and the following EKUs MAY be present:
	• Lifetime Signing OID (1.3.6.1.4.1.311.10.3.13)
	• id-kp-emailProtection
	• Document Signing (1.3.6.1.4.1.311.3.10.3.12)

If the Certificate is a Timestamp Certificate, then id-kp-timeStamping MUST be present
and MUST be marked critical.
Additionally, the following EKUs MUST NOT be present:
	• anyExtendedKeyUsage
	• id-kp-serverAuth

Other values SHOULD NOT be present. If any other value is present, the CA MUST have a
business agreement with a Platform vendor requiring that EKU in order to issue a
Platform‐specific code signing certificate with that EKU
*******************************************************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_eku_missing",
		Description:   "Subscriber certificates MUST have the extended key usage extension present",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubExtKeyUsage,
	})
}

func NewSubExtKeyUsage() lint.LintInterface {
	return &subExtKeyUsage{}
}

func (l *subExtKeyUsage) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subExtKeyUsage) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.EkuSynOid) {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
