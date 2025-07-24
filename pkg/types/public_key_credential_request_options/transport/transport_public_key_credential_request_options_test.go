package transport

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalTransportPublicKeyCredentialRequestOptions(t *testing.T) {
	const input = `
		{
		  "challenge": "ARPMOhM73buHRln5qPoidN5vHWsHl-l5Du2q5ipfikFnTadKdbWa6EvCLRPXiDuvz-YsbnuwcSilhRLn84DEzQ",
		  "rpId": "alt-shift.se"
		}
	`

	var transportPublicKeyCredentialRequestOptions TransportPublicKeyCredentialRequestOptions

	err := json.Unmarshal([]byte(input), &transportPublicKeyCredentialRequestOptions)
	if err != nil {
		t.Error(err)
	}
}
