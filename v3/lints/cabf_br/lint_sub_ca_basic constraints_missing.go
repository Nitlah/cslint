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

type subCABasicConstraintsMissing struct{}

/************************************************
BRs:7.1.2.2d

basicConstraints
This extension MUST be present and MUST be marked critical. The cA field MUST be set
true. The pathLenConstraint field MAY be present.

************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_ca_basic_constraints_missing",
		Description:   "This extension MUST be present and MUST be marked critical.",
		Citation:      "CSBRs: 7.1.2.1, RFC 5280: 4.2.1.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.RFC2459Date,
		Lint:          NewsubCABasicConstraintsMissing,
	})
}

func NewsubCABasicConstraintsMissing() lint.LintInterface {
	return &subCABasicConstraintsMissing{}
}

func (l *subCABasicConstraintsMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c)
}

func (l *subCABasicConstraintsMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.BasicConstOID) {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
