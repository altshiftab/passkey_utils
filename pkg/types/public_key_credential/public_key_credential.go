package public_key_credential

import (
	"github.com/altshiftab/passkeys_utils/pkg/types/authenticator_response"
)

type PublicKeyCredential struct {
	Id              []byte
	Type            string
	RawId           []byte
	Response        authenticator_response.AuthenticatorResponse
	ClientExtension map[string]any
}
