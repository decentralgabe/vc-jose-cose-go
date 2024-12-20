package cid

import (
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/decentralgabe/vc-jose-cose-go/util"
)

const (
	TypeJSONWebKey string = "JsonWebKey"
	TypeMultikey   string = "Multikey"
)

// Document data model as per https://www.w3.org/TR/controller-document/#data-model
type Document struct {
	ID                   string                     `json:"id" validate:"required"`
	AlsoKnownAs          []string                   `json:"alsoKnownAs,omitempty"`
	Controller           util.SingleOrArray[string] `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod       `json:"verificationMethod,omitempty"`
	Authentication       []VerificationMethodMap    `json:"authentication,omitempty"`
	AssertionMethod      []VerificationMethodMap    `json:"assertionMethod,omitempty"`
	KeyAgreement         []VerificationMethodMap    `json:"keyAgreement,omitempty"`
	CapabilityInvocation []VerificationMethodMap    `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []VerificationMethodMap    `json:"capabilityDelegation,omitempty"`
}

type VerificationMethod struct {
	ID                 string                     `json:"id" validate:"required"`
	Type               string                     `json:"type" validate:"required"`
	Controller         util.SingleOrArray[string] `json:"controller" validate:"required"`
	Revoked            string                     `json:"revoked,omitempty"`
	PublicKeyJWK       jwk.Key                    `json:"publicKeyJwk,omitempty"`
	SecretKeyJWK       jwk.Key                    `json:"secretKeyJwk,omitempty"`
	PublicKeyMultibase string                     `json:"publicKeyMultibase,omitempty"`
	SecretKeyMultibase string                     `json:"secretKeyMultibase,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling for VerificationMethod
func (vm *VerificationMethod) UnmarshalJSON(data []byte) error {
	// Create a temporary type without the custom UnmarshalJSON method to avoid recursion
	type VMAlias VerificationMethod
	var temp struct {
		PublicKeyJWK json.RawMessage `json:"publicKeyJwk,omitempty"`
		SecretKeyJWK json.RawMessage `json:"secretKeyJwk,omitempty"`
		*VMAlias
	}
	temp.VMAlias = (*VMAlias)(vm)

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Parse the JWKs if they exist
	if len(temp.PublicKeyJWK) > 0 {
		key, err := jwk.ParseKey(temp.PublicKeyJWK)
		if err != nil {
			return err
		}
		vm.PublicKeyJWK = key
	}

	if len(temp.SecretKeyJWK) > 0 {
		key, err := jwk.ParseKey(temp.SecretKeyJWK)
		if err != nil {
			return err
		}
		vm.SecretKeyJWK = key
	}

	return nil
}

type VerificationMethodMap struct {
}
