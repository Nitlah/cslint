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
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subCaPathLenPresent struct{}

/************************************************************************************************************
7.1.2.1. Root CA Certificate
a. basicConstraints
This extension MUST appear as a critical extension. The cA field MUST be set true. The pathLenConstraint field SHOULD NOT be present.
***********************************************************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "w_root_ca_basic_constraints_path_len_constraint_field_present",
		Description:   "Root CA certificate basicConstraint extension pathLenConstraint field SHOULD not be present",
		Citation:      "BRs: 7.1.2.1",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewSubCaPathLenPresent,
	})
}

func NewSubCaPathLenPresent() lint.LintInterface {
	return &subCaPathLenPresent{}
}

func (l *subCaPathLenPresent) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c) && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *subCaPathLenPresent) Execute(c *x509.Certificate) *lint.LintResult {
	bc := util.GetExtFromCert(c, util.BasicConstOID)
	var seq asn1.RawValue
	var isCa bool
	_, err := asn1.Unmarshal(bc.Value, &seq)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}
	if len(seq.Bytes) == 0 {
		return &lint.LintResult{Status: lint.Notice}
	}
	rest, err := asn1.Unmarshal(seq.Bytes, &isCa)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal}
	}
	if len(rest) <= 0 {
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{Status: lint.Notice}
}
