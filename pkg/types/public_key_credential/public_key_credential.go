package public_key_credential

import (
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response"
)

type PublicKeyCredential[T authenticator_attestation_response.AuthenticatorAttestationResponse | authenticator_assertion_response.AuthenticatorAssertionResponse] struct {
	Id              []byte
	Type            string
	RawId           []byte
	Response        T
	ClientExtension map[string]any
}
