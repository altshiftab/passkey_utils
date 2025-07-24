package public_key_credential_request_options

import "encoding/base64"

type PublicKeyCredentialDescriptor struct {
	Id         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge          string                          `json:"challenge"`
	Timeout            uint64                          `json:"timeout,omitempty"`
	RpId               string                          `json:"rpId,omitempty"`
	AllowedCredentials []*PublicKeyCredentialDescriptor `json:"allowedCredentials,omitempty"`
	UserVerification   string                          `json:"userVerification,omitempty"`
	Extensions         map[string]any                  `json:"extensions,omitempty"`
}

func New(challenge []byte, relayingPartyId string) *PublicKeyCredentialRequestOptions {
	return &PublicKeyCredentialRequestOptions{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		RpId: relayingPartyId,
	}
}
