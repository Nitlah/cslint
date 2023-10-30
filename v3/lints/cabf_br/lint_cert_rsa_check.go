package cabr_br

import (
	"crypto/rsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type rsaSignatureAlgorithmIdentiferCheck struct{}

/************************************************
https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/

When a root or intermediate certificate's ECDSA key is used to produce a signature, only the following algorithms may
be used, and with the following encoding requirements:

If the signing key is P-256, the signature MUST use ECDSA with SHA-256. The encoded AlgorithmIdentifier MUST match the
following hex-encoded bytes: 300a06082a8648ce3d040302.

If the signing key is P-384, the signature MUST use ECDSA with SHA-384. The encoded AlgorithmIdentifier MUST match the
following hex-encoded bytes: 300a06082a8648ce3d040303.

The above encodings consist of the corresponding OID with the parameters field omitted, as specified by RFC 5758,
Section 3.2. Certificates MUST NOT include a NULL parameter. Note this differs from RSASSA-PKCS1-v1_5, which includes
an explicit NULL.


7.1.3.2.1 RSA
The CA SHALL use one of the following signature algorithms:
	• RSASSA‐PKCS1‐v1_5 with SHA‐256
	• RSASSA‐PKCS1‐v1_5 with SHA‐384
	• RSASSA‐PKCS1‐v1_5 with SHA‐512
	• RSASSA‐PSS with SHA‐256
	• RSASSA‐PSS with SHA‐384
	• RSASSA‐PSS with SHA‐512
In addition, the CA MAY use RSASSA-PKCS1-v1_5 with SHA-1 if one of the following conditions are met:
		• It is used within Timestamp Authority Certificate and the date of the notBefore field is not greater than 2022‐04‐30; or,
		• It is used within an OCSP response; or,
		• It is used within a CRL; or,
		• It is used within a Timestamp Token and the date of the genTime field is not greater than 2022‐04‐30.
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_rsa_signature_algorithm_id_check",
		Description:   "The CA SHALL use signature algorithms list in 7.1.2.3.1",
		Citation:      "BRs: 7.1.3.2.1",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABF_CSBR_ALGO_ID_DATE,
		Lint:          NewRSASignatureAlgorithmIdentiferCheck,
	})
}

func NewRSASignatureAlgorithmIdentiferCheck() lint.LintInterface {
	return &rsaSignatureAlgorithmIdentiferCheck{}
}

func (l *rsaSignatureAlgorithmIdentiferCheck) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA
}

func (l *rsaSignatureAlgorithmIdentiferCheck) Execute(c *x509.Certificate) *lint.LintResult {
	if c.SignatureAlgorithm == x509.SHA256WithRSAPSS ||
		c.SignatureAlgorithm == x509.SHA384WithRSAPSS ||
		c.SignatureAlgorithm == x509.SHA512WithRSAPSS ||
		c.SignatureAlgorithm == x509.SHA256WithRSA ||
		c.SignatureAlgorithm == x509.SHA384WithRSA ||
		c.SignatureAlgorithm == x509.SHA512WithRSA {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
