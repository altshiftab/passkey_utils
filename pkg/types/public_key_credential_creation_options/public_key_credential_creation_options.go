package public_key_credential_creation_options

import (
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_descriptor"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_entity/public_key_credential_user_entity"
)

type PublicKeyCredentialCreationOptions struct {
	RelyingParty *RelayingParty                                                   `json:"rp"`
	User         *public_key_credential_user_entity.PublicKeyCredentialUserEntity `json:"user"`

	Challenge        string                      `json:"challenge"`
	PubKeyCredParams []*PublicKeyCredentialParam `json:"pubKeyCredParams"`

	Timeout                uint64                                                            `json:"timeout,omitempty"`
	ExcludeCredentials     []*public_key_credential_descriptor.PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelection                                           `json:"authenticatorSelection,omitempty"`
	Attestation            string                                                            `json:"attestation,omitempty"`
	Extensions             map[string]any                                                    `json:"extensions,omitempty"`
}

type RelayingParty struct {
	Name string `json:"name"`
	Id   string `json:"id,omitempty"`
}

type PublicKeyCredentialParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKeyPreference   string `json:"residentKey,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
}
