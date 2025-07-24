package public_key_credential_descriptor

type PublicKeyCredentialDescriptor struct {
	Id         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}
