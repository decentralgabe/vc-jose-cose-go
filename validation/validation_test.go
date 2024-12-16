package validation

import (
	"testing"

	"github.com/decentralgabe/vc-jose-cose-go/credential"
	"github.com/decentralgabe/vc-jose-cose-go/util"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnknownFields(t *testing.T) {
	type NotAVerifiableCredential struct {
		Context util.SingleOrArray[string] `json:"@context,omitempty" validate:"required"`
		Type    util.SingleOrArray[string] `json:"type,omitempty" validate:"required"`
		ID      string                     `json:"id,omitempty"`
		// either a URI or an object containing an `id` property.
		Issuer *credential.IssuerHolder `json:"issuer,omitempty" validate:"required"`
		// https://www.w3.org/TR/xmlschema11-2/#dateTimes
		ValidFrom  string `json:"validFrom,omitempty" validate:"required"`
		ValidUntil string `json:"validUntil,omitempty"`
		// This is where the subject's ID *may* be present
		CredentialSubject credential.Subject                    `json:"credentialSubject,omitempty"`
		CredentialSchema  util.SingleOrArray[credential.Schema] `json:"credentialSchema,omitempty"`
		CredentialStatus  util.SingleOrArray[any]               `json:"credentialStatus,omitempty"`
		TermsOfUse        util.SingleOrArray[any]               `json:"termsOfUse,omitempty"`
		Evidence          util.SingleOrArray[any]               `json:"evidence,omitempty"`
		UnknownField      string                                `json:"unknownField,omitempty"`
	}

	unknown := NotAVerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		},
		UnknownField: "unknown",
	}

	unknownBytes, err := json.Marshal(unknown)
	require.NoError(t, err)

	vc, err := DecodeVC(unknownBytes)
	assert.Error(t, err)
	assert.Empty(t, vc)
}
