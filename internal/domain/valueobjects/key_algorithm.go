package valueobjects

type KeyAlgorithm string

const (
	RSA     KeyAlgorithm = "RSA"
	ECDSA   KeyAlgorithm = "ECDSA" 
	Ed25519 KeyAlgorithm = "Ed25519"
)

func (a KeyAlgorithm) IsValid() bool {
	switch a {
	case RSA, ECDSA, Ed25519:
		return true
	default:
		return false
	}
}

func (a KeyAlgorithm) String() string {
	return string(a)
}