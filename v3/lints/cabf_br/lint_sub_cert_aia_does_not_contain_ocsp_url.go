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
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subCertOcspUrl struct{}

/**************************************************************************************************
BRs: 7.1.2.3
authorityInformationAccess
This extension MUST be present. It MUST NOT be marked critical.
It MUST contain the HTTP URL of the Issuing CA’s certificate (accessMethod =
1.3.6.1.5.5.7.48.2). If the CA provides OCSP responses, it MUST contain the HTTP URL of the
Issuing CA’s OCSP responder (accessMethod = 1.3.6.1.5.5.7.48.1).
***************************************************************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sub_cert_aia_does_not_contain_ocsp_url",
		Description:   "Subscriber Certificate: . If the CA provides OCSP responses, it MUST contain the HTTP URL of the Issuing CA’s OCSP responder (accessMethod = 1.3.6.1.5.5.7.48.1).",
		Citation:      "CSBRs: 7.1.2.3",
		Source:        lint.CSBaselineRequirements,
		EffectiveDate: util.CSBREffectiveDate,
		Lint:          NewSubCertOcspUrl,
	})
}

func NewSubCertOcspUrl() lint.LintInterface {
	return &subCertOcspUrl{}
}

func (l *subCertOcspUrl) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.AiaOID)
}

func (l *subCertOcspUrl) Execute(c *x509.Certificate) *lint.LintResult {
	if c.OCSPServer != nil {
		for _, url := range c.OCSPServer {
			if strings.HasPrefix(url, "http://") {
				return &lint.LintResult{Status: lint.Pass}
			}
		}
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
