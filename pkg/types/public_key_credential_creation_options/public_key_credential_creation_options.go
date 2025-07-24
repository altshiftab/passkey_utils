package public_key_credential_creation_options

import (
	"encoding/base64"
)

type PublicKeyCredentialCreationOptions struct {
	Challenge              string                         `json:"challenge"`
	Timeout                uint64                         `json:"timeout,omitempty"`
	RelyingParty           *RelayingParty                 `json:"rp"`
	User                   *UserEntity                    `json:"user"`
	PubKeyCredParams       []*PublicKeyCredentialParam    `json:"pubKeyCredParams"`
	ExcludeCredentials     []*ExcludedPublicKeyCredential `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelection        `json:"authenticatorSelection,omitempty"`
	Attestation            string                         `json:"attestation,omitempty"`
}

type RelayingParty struct {
	Name string `json:"name"`
	Id   string `json:"id,omitempty"`
}

type UserEntity struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type ExcludedPublicKeyCredential struct {
	Id         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKeyPreference   string `json:"residentKey,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
}

func New(
	userId string,
	userName string,
	displayName string,
	relayingParty *RelayingParty,
	challenge []byte,
) (*PublicKeyCredentialCreationOptions, error) {
	// TODO: Lookup excluded credentials.
	var excludeCredentials []*ExcludedPublicKeyCredential

	return &PublicKeyCredentialCreationOptions{
		RelyingParty: relayingParty,
		Challenge:    base64.RawURLEncoding.EncodeToString(challenge),
		User: &UserEntity{
			Id:          base64.RawURLEncoding.EncodeToString([]byte(userId)),
			Name:        userName,
			DisplayName: displayName,
		},
		PubKeyCredParams: []*PublicKeyCredentialParam{
			// ECDSA P-256
			{Type: "public-key", Alg: -7},
		},
		ExcludeCredentials: excludeCredentials,
		// TODO: Must this be `platform`?
		AuthenticatorSelection: &AuthenticatorSelection{
			AuthenticatorAttachment: "platform",
			ResidentKeyPreference:   "required",
			RequireResidentKey:      true,
		},
		Attestation: "none",
	}, nil
}
