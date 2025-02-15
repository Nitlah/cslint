package legacy

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
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type authorityKeyIdMissing struct{}

/***********************************************************************
RFC 5280: 4.2.1.1
The keyIdentifier field of the authorityKeyIdentifier extension MUST
   be included in all certificates generated by conforming CAs to
   facilitate certification path construction.  There is one exception;
   where a CA distributes its public key in the form of a "self-signed"
   certificate, the authority key identifier MAY be omitted.  The
   signature on a self-signed certificate is generated with the private
   key associated with the certificate's subject public key.  (This
   proves that the issuer possesses both the public and private keys.)
   In this case, the subject and authority key identifiers would be
   identical, but only the subject key identifier is needed for
   certification path building.

authorityKeyIdentifier：该字段必须存在且绝对不能被标记为关键扩展
***********************************************************************/

//func init() {
//	lint.RegisterLint(&lint.Lint{
//		Name:          "e_ext_authority_key_identifier_missing",
//		Description:   "CAs must support key identifiers and include them in all certificates",
//		Citation:      "RFC 5280: 4.2 & 4.2.1.1",
//		Source:        lint.RFC5280,
//		EffectiveDate: util.RFC2459Date,
//		Lint:          NewAuthorityKeyIdMissing,
//	})
//}

func NewAuthorityKeyIdMissing() lint.LintInterface {
	return &authorityKeyIdMissing{}
}

// CheckApplies 根证书没有该字段
func (l *authorityKeyIdMissing) CheckApplies(c *x509.Certificate) bool {
	return !util.IsRootCA(c)
}

func (l *authorityKeyIdMissing) Execute(c *x509.Certificate) *lint.LintResult {
	if !util.IsExtInCert(c, util.AuthkeyOID) && !util.IsSelfSigned(c) {
		if util.IsExtInCert(c, util.AuthkeyDeprecatedOID) {
			return &lint.LintResult{Status: lint.Warn,
				Details: fmt.Sprintf("Certificate contains deprecated authorityKeyIdentifier"),
			}
		}
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
