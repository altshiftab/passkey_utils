package validation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	passkeyUtilsErrors "github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_data"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_assertion_response"
	"github.com/altshiftab/passkey_utils/pkg/types/authenticator_response/authenticator_attestation_response"
	"github.com/altshiftab/passkey_utils/pkg/types/collected_client_data"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential"
	"math/big"
	"slices"
)

const (
	WebauthnCreateType     = "webauthn.create"
	WebauthnGetType        = "webauthn.get"
	ExpectedCredentialType = "public-key"
)

type authenticatorResponseTypes interface {
	authenticator_response.AuthenticatorResponse
	authenticator_attestation_response.AuthenticatorAttestationResponse | authenticator_assertion_response.AuthenticatorAssertionResponse
}

func validatePublicKeyCredential[T authenticatorResponseTypes](
	credential *public_key_credential.PublicKeyCredential[T],
	expectedCollectedClientDataType string,
	expectedCollectedClientDataChallenge []byte,
	expectedCollectedClientDataOrigin string,
	expectedRpId string,
	previousSignatureCount uint32,
	attestCredentialData bool,
) error {
	if expectedCollectedClientDataType == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedCollectedClientDataType)
	}

	if len(expectedCollectedClientDataChallenge) == 0 {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyChallenge)
	}

	if expectedCollectedClientDataOrigin == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedOrigin)
	}

	if expectedRpId == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedRpId)
	}

	if credential == nil {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrNilPublicKeyCredential,
		)
	}

	if len(credential.Id) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyCredentialId,
		)
	}

	observedCredentialType := credential.Type
	if observedCredentialType != ExpectedCredentialType {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w: %q",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrCredentialTypeMismatch,
				observedCredentialType,
			),
			observedCredentialType,
			ExpectedCredentialType,
		)
	}

	response := credential.Response

	collectedClientData := response.GetClientDataJson()
	if collectedClientData == nil {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrNilCollectedClientData,
			),
		)
	}

	authenticatorData := response.GetAuthenticatorData()
	if authenticatorData == nil {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrNilAuthenticatorData,
			),
		)
	}

	err := ValidateCollectedClientData(
		collectedClientData,
		expectedCollectedClientDataType,
		expectedCollectedClientDataChallenge,
		expectedCollectedClientDataOrigin,
	)
	if err != nil {
		return motmedelErrors.New(fmt.Errorf("validate collected client data: %w", err), collectedClientData)
	}

	err = ValidateAuthenticatorData(
		authenticatorData,
		expectedRpId,
		previousSignatureCount,
		attestCredentialData,
		false,
	)
	if err != nil {
		return motmedelErrors.New(fmt.Errorf("validate authenticator data: %w", err), authenticatorData)
	}

	return nil
}

func ValidateAttestationPublicKeyCredential(
	credential *public_key_credential.AttestationPublicKeyCredential,
	expectedCollectedClientDataChallenge []byte,
	expectedCollectedClientDataOrigin string,
	expectedRpId string,
	allowedPublicKeyAlgorithms []int,
) error {
	if len(expectedCollectedClientDataChallenge) == 0 {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyChallenge)
	}

	if expectedCollectedClientDataOrigin == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedOrigin)
	}

	if expectedRpId == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedRpId)
	}

	if len(allowedPublicKeyAlgorithms) == 0 {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyAllowedPublicKeyAlgorithms)
	}

	if credential == nil {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrNilPublicKeyCredential,
		)
	}

	err := validatePublicKeyCredential(
		credential,
		WebauthnCreateType,
		expectedCollectedClientDataChallenge,
		expectedCollectedClientDataOrigin,
		expectedRpId,
		0,
		true,
	)
	if err != nil {
		return fmt.Errorf("validate public key credential: %w", err)
	}

	response := credential.Response

	if len(response.PublicKey) == 0 {
		return fmt.Errorf(
			"%w: %w (authenticator attestation response)",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyPublicKey,
		)
	}

	if len(response.Transports) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyTransports,
		)
	}

	observedPublicKeyAlgorithm := response.PublicKeyAlgorithm
	if !slices.Contains(allowedPublicKeyAlgorithms, observedPublicKeyAlgorithm) {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w: %v",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrPublicKeyAlgorithmMismatch,
				observedPublicKeyAlgorithm,
			),
			observedPublicKeyAlgorithm,
			allowedPublicKeyAlgorithms,
		)
	}

	return nil
}

func ValidateEcdsaAssertionPublicKeyCredential(
	credential *public_key_credential.AssertionPublicKeyCredential,
	rawClientDataJson []byte,
	rawAuthenticatorData []byte,
	expectedCollectedClientDataChallenge []byte,
	expectedCollectedClientDataOrigin string,
	expectedRpId string,
	previousSignatureCount uint32,
	storedPublicKey *ecdsa.PublicKey,
) error {
	if len(expectedCollectedClientDataChallenge) == 0 {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyChallenge)
	}

	if expectedCollectedClientDataOrigin == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedOrigin)
	}

	if expectedRpId == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedRpId)
	}

	if storedPublicKey == nil {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrNilStoredPublicKey)
	}

	if credential == nil {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrNilPublicKeyCredential,
		)
	}

	if len(rawClientDataJson) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyRawClientDataJson,
		)
	}

	if len(rawAuthenticatorData) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyRawAuthenticatorData,
		)
	}

	err := validatePublicKeyCredential(
		credential,
		WebauthnGetType,
		expectedCollectedClientDataChallenge,
		expectedCollectedClientDataOrigin,
		expectedRpId,
		previousSignatureCount,
		false,
	)
	if err != nil {
		return fmt.Errorf("validate public key credential: %w", err)
	}

	response := credential.Response

	signature := response.Signature
	if len(signature) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptySignature,
		)
	}

	if len(response.UserHandle) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyUserHandle,
		)
	}

	var ecdsaSig struct {
		R, S *big.Int
	}

	_, err = asn1.Unmarshal(signature, &ecdsaSig)
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w (signature): asn1 unmarshal %w",
				motmedelErrors.ErrValidationError,
				err,
			),
			signature,
		)
	}

	clientDataJsonHash := sha256.Sum256(rawClientDataJson)
	signedDataHash := sha256.Sum256(bytes.Join([][]byte{rawAuthenticatorData, clientDataJsonHash[:]}, nil))

	if ok := ecdsa.Verify(storedPublicKey, signedDataHash[:], ecdsaSig.R, ecdsaSig.S); !ok {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrSignatureVerifyFailure,
			),
			signedDataHash,
			ecdsaSig,
		)
	}

	return nil
}

func ValidateCollectedClientData(
	clientData *collected_client_data.CollectedClientData,
	expectedType string,
	expectedChallenge []byte,
	expectedOrigin string,
) error {
	if expectedType == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedCollectedClientDataType)
	}

	if len(expectedChallenge) == 0 {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyChallenge)
	}

	if expectedOrigin == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedOrigin)
	}

	if clientData == nil {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrNilCollectedClientData,
		)
	}

	observedType := clientData.Type
	if observedType != expectedType {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w: %q",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrCollectedClientDataTypeMismatch,
				observedType,
			),
			observedType,
			expectedType,
		)
	}

	observedChallenge := clientData.Challenge
	if !bytes.Equal(expectedChallenge, observedChallenge) {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w: %v",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrChallengeMismatch,
				observedChallenge,
			),
			observedChallenge,
			expectedChallenge,
		)
	}

	observedOrigin := clientData.Origin
	if observedOrigin != expectedOrigin {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w: %q",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrOriginMismatch,
				observedOrigin,
			),
			observedOrigin,
			expectedOrigin,
		)
	}

	return nil
}

func ValidateAuthenticatorData(
	authenticatorData *authenticator_data.AuthenticatorData,
	expectedRpId string,
	previousSignatureCount uint32,
	validateAttestedCredential bool,
	verifyUser bool,
) error {
	if expectedRpId == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyExpectedRpId)
	}

	if authenticatorData == nil {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrNilAuthenticatorData,
		)
	}

	if validateAttestedCredential {
		attestedCredential := authenticatorData.AttestedCredential
		if attestedCredential == nil {
			return fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrNilAttestedCredential,
			)
		}

		if len(attestedCredential.CredentialId) == 0 {
			return fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrEmptyCredentialId,
			)
		}

		if len(attestedCredential.PublicKey) == 0 {
			return fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrEmptyPublicKey,
			)
		}

		if len(attestedCredential.Aaguid) == 0 {
			return fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrEmptyAaguid,
			)
		}
	}

	observedRpIdHash := authenticatorData.RpIdHash
	if len(observedRpIdHash) == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrEmptyRpIdHash,
		)
	}

	expectedRpIdHash := sha256.Sum256([]byte(expectedRpId))
	if !bytes.Equal(observedRpIdHash, expectedRpIdHash[:]) {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrRpIdHashMismatch,
			),
			observedRpIdHash,
			expectedRpIdHash,
		)
	}

	// User presence
	if authenticatorData.Flags&0x01 == 0 {
		return fmt.Errorf(
			"%w: %w",
			motmedelErrors.ErrValidationError,
			passkeyUtilsErrors.ErrUserNotPresent,
		)
	}

	if verifyUser {
		// User verification
		if authenticatorData.Flags&0x04 == 0 {
			return fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrUserNotVerified,
			)
		}
	}

	observedSignCount := authenticatorData.SignCount
	if previousSignatureCount != 0 && observedSignCount <= previousSignatureCount {
		return motmedelErrors.New(
			fmt.Errorf(
				"%w: %w",
				motmedelErrors.ErrValidationError,
				passkeyUtilsErrors.ErrUnexpectedSignatureCount,
			),
			observedSignCount,
			previousSignatureCount,
		)
	}

	return nil
}
