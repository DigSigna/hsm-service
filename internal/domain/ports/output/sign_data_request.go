package output

type SignDataRequest struct {
	KeyID     string
	Data      []byte
	Algorithm string
}
