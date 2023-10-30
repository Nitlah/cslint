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

type subCAEKUCrit struct{}

/************************************************
BRs: 7.1.2.2g extkeyUsage
This extension MUST be present and SHOULD NOT be marked critical.

************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "w_sub_ca_eku_critical",
		Description:   "This extension MUST be present and SHOULD NOT be marked critical.",
		Citation:      "BRs: 7.1.2.2",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABV116Date,
		Lint:          NewSubCAEKUCrit,
	})
}

func NewSubCAEKUCrit() lint.LintInterface {
	return &subCAEKUCrit{}
}

func (l *subCAEKUCrit) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && util.IsExtInCert(c, util.EkuSynOid)
}

func (l *subCAEKUCrit) Execute(c *x509.Certificate) *lint.LintResult {
	if e := util.GetExtFromCert(c, util.EkuSynOid); e.Critical {
		return &lint.LintResult{Status: lint.Warn}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
