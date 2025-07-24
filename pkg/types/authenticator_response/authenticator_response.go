package authenticator_response

import (
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkey_utils/pkg/types/collected_client_data"
)

type AuthenticatorResponse interface {
	GetClientDataJson() *collected_client_data.CollectedClientData
	GetAuthenticatorData() *authenticator_data.AuthenticatorData
}

type TransportAuthenticatorResponse interface {
	GetClientDataJson() []byte
	GetAuthenticatorData() []byte
}
