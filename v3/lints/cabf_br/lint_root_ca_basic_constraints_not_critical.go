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

type rootCABasicConstraintsCritical struct{}

/************************************************
RFC 5280: 4.2.1.3

basicConstraints：该字段必须被设置为关键扩展
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_root_ca_basic_constraints_not_critical",
		Description:   "Root CA Certificate: basicConstraints: This extension MUST appear as a critical extension.",
		Citation:      "CSBRs: 7.1.2.1, RFC 5280: 4.2.1.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.RFC3280Date,
		Lint:          NewRootCABasicConstraintsCritical,
	})
}

func NewRootCABasicConstraintsCritical() lint.LintInterface {
	return &rootCABasicConstraintsCritical{}
}

func (l *rootCABasicConstraintsCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c) && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *rootCABasicConstraintsCritical) Execute(c *x509.Certificate) *lint.LintResult {
	if e := util.GetExtFromCert(c, util.BasicConstOID); e.Critical {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
