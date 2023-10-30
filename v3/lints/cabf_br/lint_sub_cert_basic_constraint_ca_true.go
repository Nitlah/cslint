package cabr_br

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/lints"
	"github.com/zmap/zlint/v3/util"
)

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

/*
modify
basicConstraints：该字段必须被设置为关键扩展
*/

import (
	"github.com/zmap/zcrypto/x509"
)

type subCertBasicConstraintsCATrue struct{}

/*
7.1.2.2d
This extension MUST be present and MUST be marked critical. The cA field MUST be set
true. The pathLenConstraint field MAY be present.
*/
func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_basic_constraints_ca_true",
		Description:   "This extension MUST be present and MUST be marked critical.",
		Citation:      "BRs: 7.1.2.2d",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewSubCertBasicConstraintsCATrue,
	})
}

func NewSubCertBasicConstraintsCATrue() lint.LintInterface {
	return &subCertBasicConstraintsCATrue{}
}

func (l *subCertBasicConstraintsCATrue) CheckApplies(c *x509.Certificate) bool {

	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *subCertBasicConstraintsCATrue) Execute(c *x509.Certificate) *lint.LintResult {
	e := util.GetExtFromCert(c, util.BasicConstOID)
	var constraints lints.BasicConstraints
	_, err := asn1.Unmarshal(e.Value, &constraints)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}
	if constraints.IsCA {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}

}
