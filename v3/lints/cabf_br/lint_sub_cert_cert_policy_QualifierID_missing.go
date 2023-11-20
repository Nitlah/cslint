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

type subCertPolicyQualifierIDMissing struct{}

/******************************************************************************
BRs: 7.1.2.3
certificatePolicies
This extension MUST be present and SHOULD NOT be marked critical.
certificatePolicies:policyIdentifier (Required)
A Policy Identifier, defined by the issuing CA, that indicates a Certificate Policy asserting
the issuing CA’s adherence to and compliance with these Requirements.
******************************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "w_sub_cert_certificate_policies_QualifiersId_missing",
		Description:   "certificatePolicies:policyQualifiers:policyQualifierId (Recommended)",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubCertPolicyQualifierIDMissing,
	})
}

func NewSubCertPolicyQualifierIDMissing() lint.LintInterface {
	return &subCertPolicyQualifierIDMissing{}
}

func (l *subCertPolicyQualifierIDMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.CertPolicyOID)
}

func (l *subCertPolicyQualifierIDMissing) Execute(c *x509.Certificate) *lint.LintResult {
	//e := util.GetExtFromCert(c, util.CertPolicyOID)
	if len(c.QualifierId) == 0 {
		return &lint.LintResult{Status: lint.Warn}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
