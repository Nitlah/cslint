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

/*
6.3.2 Certificate operational periods and key pair usage periods
The validity period for a Code Signing Certificate issued to a Subscriber or Signing Service MUST
NOT exceed 39 months.
The Timestamp Authority MUST use a new Timestamp Certificate with a new private key no later
than every 15 months to minimize the impact to users in the event that a Timestamp Certificate’s
private key is compromised. The validity for a Timestamp Certificate must not exceed 135 months.
The Timestamp Certificate MUST meet the requirements in Section 6.1.5 for the communicated
time period.
*/
type timeStampValidTooLong struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_time_stamp_valid_time_too_long",
		Description:   "time stamp certificates must be 135 months in validity or less",
		Citation:      "BRs:6.3.2",
		Source:        lint.CABFEVGuidelines,
		EffectiveDate: util.ZeroDate,
		Lint:          NewTimeStampValidTooLong,
	})
}

func NewTimeStampValidTooLong() lint.LintInterface {
	return &timeStampValidTooLong{}
}

func (l *timeStampValidTooLong) CheckApplies(c *x509.Certificate) bool {
	timestamp := false
	if c.ExtKeyUsage != nil {
		for _, v := range c.ExtKeyUsage {
			if v == x509.ExtKeyUsageTimeStamping {
				timestamp = true
				break
			}
		}
	}
	return timestamp && util.IsSubscriberCert(c)
}

func (l *timeStampValidTooLong) Execute(c *x509.Certificate) *lint.LintResult {
	if c.NotBefore.AddDate(0, 135, 0).Before(c.NotAfter) {
		return &lint.LintResult{Status: lint.Error}
	}
	return &lint.LintResult{Status: lint.Pass}
}
