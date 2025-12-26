package transport

import (
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_creation_options"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_descriptor"
	transportPublicKeyCredentialUserEntity "github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_entity/public_key_credential_user_entity/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

type PublicKeyCredentialCreationOptions struct {
	RelyingParty *public_key_credential_creation_options.RelayingParty                 `json:"rp"`
	User         *transportPublicKeyCredentialUserEntity.PublicKeyCredentialUserEntity `json:"user"`

	Challenge        *transport.Base64URL                                               `json:"challenge"`
	PubKeyCredParams []*public_key_credential_creation_options.PublicKeyCredentialParam `json:"pubKeyCredParams"`

	Timeout                uint64                                                            `json:"timeout,omitempty"`
	ExcludeCredentials     []*public_key_credential_descriptor.PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *public_key_credential_creation_options.AuthenticatorSelection    `json:"authenticatorSelection,omitempty"`
	Attestation            string                                                            `json:"attestation,omitempty"`
	Extensions             map[string]any                                                    `json:"extensions,omitempty"`
}
