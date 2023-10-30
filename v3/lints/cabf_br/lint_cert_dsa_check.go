package cabr_br

import (
	"github.com/zmap/zcrypto/dsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type dsaSignatureAlgorithmIdentiferCheck struct{}

/************************************************
The CA SHALL use the following signature algorithm:
	• DSA with SHA‐256
In addition, the CA MAY use DSA with SHA-1 if one of the following conditions are met:
	• It is used within Timestamp Authority Certificate and the date of the notBefore field is not greater than 2022‐04‐30; or,
	• It is used within an OCSP response; or,
	• It is used within a CRL; or,
	• It is used within a Timestamp Token and the date of the genTime field is not greater than 2022‐04‐30.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_dsa_signature_algorithm_id_check",
		Description:   "The CA SHALL use the following signature algorithm: • DSA with SHA‐256",
		Citation:      "7.1.3.2.3",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewDSASignatureAlgorithmIdentiferCheck,
	})
}

func NewDSASignatureAlgorithmIdentiferCheck() lint.LintInterface {
	return &dsaSignatureAlgorithmIdentiferCheck{}
}

func (l *dsaSignatureAlgorithmIdentiferCheck) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*dsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.DSA
}

func (l *dsaSignatureAlgorithmIdentiferCheck) Execute(c *x509.Certificate) *lint.LintResult {
	if c.SignatureAlgorithmOID.Equal(util.OidSignatureSHA256withDSA) {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
