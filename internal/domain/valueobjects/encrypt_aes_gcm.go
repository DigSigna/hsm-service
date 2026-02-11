package valueobjects

import "errors"

type EncryptAESGCM struct {
	IV         []byte
	Ciphertext []byte
	Tag        []byte
	Algorithm  string // "AES-256-GCM"
	KeyID      string // key identifier used
}

func (e EncryptAESGCM) IsValid() bool {
	return len(e.IV) == 12 && len(e.Tag) == 16 && len(e.Ciphertext) > 0 && e.Algorithm == "AES-256-GCM"
}

func (e EncryptAESGCM) ToBytes() []byte {
	// Solo si necesitas concatenar para compatibilidad
	result := make([]byte, 0, len(e.IV)+len(e.Ciphertext)+len(e.Tag))
	result = append(result, e.IV...)
	result = append(result, e.Ciphertext...)
	result = append(result, e.Tag...)
	return result
}

func NewEncryptedDataFromBytes(data []byte) (EncryptAESGCM, error) {
	// Parsear IV(12)|Ciphertext|Tag(16)
	if len(data) < 28 { // IV(12) + Tag(16) mínimo
		return EncryptAESGCM{}, errors.New("invalid encrypted data length")
	}

	iv := data[:12]
	tag := data[len(data)-16:]
	ciphertext := data[12 : len(data)-16]

	return EncryptAESGCM{
		IV:         iv,
		Ciphertext: ciphertext,
		Tag:        tag,
		Algorithm:  "AES-256-GCM",
	}, nil
}
