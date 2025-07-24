package collected_client_data

type CollectedClientData struct {
	Type        string `json:"type,omitempty"`
	Challenge   []byte `json:"challenge,omitempty"`
	Origin      string `json:"origin,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}
