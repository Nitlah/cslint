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
	"strings"
)

type evSubjectBussinessCategory struct{}

/************************************************
BRs: 7.1.2.1e
The	Certificate	Subject	MUST contain the following:
‐	countryName	(OID 2.5.4.6).
This field MUST	contain	the	two‐letter	ISO	3166‐1 country code	for	the country
in which the CA’s place	of business	is located.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_ev_subject_bussiness_category_valid",
		Description: "This field MUST contain one of the following strings:" +
			" Private Organization,Government Entity, Business Entity, or Non-Commercial Entity depending upon " +
			"whether the Subject qualifies under the terms of Section 8.5.2, 8.5.3, 8.5.4 or 8.5.5 of these Guidelines, respectively",
		Citation:      "CSBRs: 7.1.4.2.4",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.ZeroDate,
		Lint:          NewSubjectBussinessCategoryValid,
	})
}

func NewSubjectBussinessCategoryValid() lint.LintInterface {
	return &evSubjectBussinessCategory{}
}

func (l *evSubjectBussinessCategory) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.TypeInName(&c.Subject, util.BusinessOID)
}

func (l *evSubjectBussinessCategory) Execute(c *x509.Certificate) *lint.LintResult {
	category := map[string]int{"private organization": 1, "government entity": 1, "business entity": 1, "non-commercial entity": 1}
	for _, v := range c.Subject.Names {
		if util.BusinessOID.Equal(v.Type) {
			if _, exists := category[strings.ToLower(v.Value.(string))]; exists {
				return &lint.LintResult{Status: lint.Pass}
			}
		}
	}
	return &lint.LintResult{Status: lint.Error}
}
