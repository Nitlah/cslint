package cabr_br

import (
	"crypto/ecdsa"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type ecdsaSignatureAlgorithmIdentiferCheck struct{}

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


7.1.3.2.2 ECDSA
The CA SHALL use one of the following signature algorithms:
	• ECDSA with SHA‐256
	• ECDSA with SHA‐384
	• ECDSA with SHA‐512
************************************************/

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ecdsa_signature_algorithm_id_check",
		Description:   "The CA SHALL use one of the following signature algorithms: • ECDSA with SHA‐256 • ECDSA with SHA‐384 • ECDSA with SHA‐512",
		Citation:      "7.1.3.2.2",
		Source:        lint.CABFBaselineRequirements,
		EffectiveDate: util.CABEffectiveDate,
		Lint:          NewECDSASignatureAlgorithmIdentiferCheck,
	})
}

func NewECDSASignatureAlgorithmIdentiferCheck() lint.LintInterface {
	return &ecdsaSignatureAlgorithmIdentiferCheck{}
}

func (l *ecdsaSignatureAlgorithmIdentiferCheck) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*ecdsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.ECDSA
}

func (l *ecdsaSignatureAlgorithmIdentiferCheck) Execute(c *x509.Certificate) *lint.LintResult {
	if c.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		c.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		c.SignatureAlgorithm == x509.ECDSAWithSHA512 {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}
}
