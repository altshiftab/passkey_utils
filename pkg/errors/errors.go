package errors

import (
	"errors"
)

var (
	ErrEmptyCredentialId        = errors.New("empty credential id")
	ErrNilAuthenticatorData     = errors.New("nil authenticator data")
	ErrRpIdHashMismatch         = errors.New("rp id hash mismatch")
	ErrUserNotPresent           = errors.New("user not present")
	ErrUserNotVerified          = errors.New("user not verified")
	ErrUnexpectedSignatureCount = errors.New("unexpected signature count")
	ErrNilAttestedCredential    = errors.New("nil attested credential")
	ErrEmptyPublicKey           = errors.New("empty public key")
	ErrEmptyAaguid              = errors.New("empty aaguid")
	ErrNilUserEntity            = errors.New("nil user entity")

	ErrNilPublicKeyCredential = errors.New("nil public key credential")
	ErrNilCollectedClientData = errors.New("nil collected client data")
	ErrEmptyExpectedCollectedClientDataType = errors.New("empty expected collected client data type")
	ErrEmptyChallenge = errors.New("empty challenge")
	ErrCollectedClientDataTypeMismatch      = errors.New("collected client data type mismatch")
	ErrChallengeMismatch        = errors.New("challenge mismatch")
	ErrEmptyExpectedOrigin = errors.New("empty expected origin")
	ErrOriginMismatch = errors.New("origin mismatch")
	ErrEmptyExpectedRpId = errors.New("empty expected rp id")
	ErrCredentialTypeMismatch = errors.New("credential type mismatch")
	ErrEmptyAllowedPublicKeyAlgorithms = errors.New("empty allowed public key algorithms")
	ErrEmptyTransports = errors.New("empty transports")
	ErrPublicKeyAlgorithmMismatch = errors.New("public key algorithm mismatch")
	ErrNilStoredPublicKey = errors.New("nil stored public key")
	ErrEmptyRawClientDataJson = errors.New("empty raw client data json")
	ErrEmptyRawAuthenticatorData = errors.New("empty raw authenticator data")
	ErrEmptySignature = errors.New("empty signature")
	ErrEmptyUserHandle = errors.New("empty user handle")
	ErrSignatureVerifyFailure = errors.New("signature verify failure")
	ErrEmptyRpIdHash = errors.New("empty rp id hash")
)
