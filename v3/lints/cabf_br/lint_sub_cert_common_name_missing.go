package cabr_br

import (
	"github.com/zmap/zlint/v3/lint"
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

import (
	"github.com/zmap/zcrypto/x509"
)

type subCertCommonNameMissing struct{}

/************************************************
7.1.4.2.2 Subject distinguished name fields ‑ EV and Non‑EV Code Signing Certificates
a. Certificate Field: subject:commonName (OID 2.5.4.3)
	Required/Optional: Required
	Contents: This field MUST contain the Subject’s legal name as verified under Section 3.2.2 or3.2.3.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:        "e_sub_cert_common_name_missing",
		Description: "EV and Non‑EV Code Signing Certificates MUST have a commonName present in subject information",
		Citation:    "CSBRs: 7.1.4.2",
		Source:      lint.CSBaselineRequirements,
		// todo:实际还没确定
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewSubCertCommonNameMissing,
	})
}

func NewSubCertCommonNameMissing() lint.LintInterface {
	return &subCertCommonNameMissing{}
}

func (l *subCertCommonNameMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertCommonNameMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.CommonName != "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
