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

type subCertPolicyEmpty struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_cert_policy_empty",
		Description:   "Subscriber certificates must contain at least one policy identifier that indicates adherence to CAB standards",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubCertPolicyEmpty,
	})
}

func NewSubCertPolicyEmpty() lint.LintInterface {
	return &subCertPolicyEmpty{}
}

func (l *subCertPolicyEmpty) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertPolicyEmpty) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.CertPolicyOID) && c.PolicyIdentifiers != nil {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
