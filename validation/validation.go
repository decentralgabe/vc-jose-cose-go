package validation

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	sdjwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/decentralgabe/vc-jose-cose-go/credential"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/veraison/go-cose"
)

// DecodeVC decodes a VerifiableCredential from a byte slice and returns an error if the data contains unknown fields.
func DecodeVC(data []byte) (*credential.VerifiableCredential, error) {
	var vc credential.VerifiableCredential
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vc); err != nil {
		return nil, fmt.Errorf("unknown field in credential: %w", err)
	}
	return &vc, nil
}

// DecodeVP decodes a VerifiablePresentation from a byte slice and returns an error if the data contains unknown fields.
func DecodeVP(data []byte) (*credential.VerifiablePresentation, error) {
	var vp credential.VerifiablePresentation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vp); err != nil {
		return nil, fmt.Errorf("unknown field in presentation: %w", err)
	}
	return &vp, nil
}

// HasVCorVPClaim checks if the payload contains either a "vc" or "vp" claim.
func HasVCorVPClaim(payload []byte) error {
	var payloadMap map[string]any
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	if _, hasVC := payloadMap["vc"]; hasVC {
		return fmt.Errorf("payload contains 'vc' claim, which is not allowed")
	}

	if _, hasVP := payloadMap["vp"]; hasVP {
		return fmt.Errorf("payload contains 'vp' claim, which is not allowed")
	}

	return nil
}

// GetValidDataURLPrefixes returns the list of valid data URL prefixes for enveloped
// Verifiable Credentials and Presentations.
func GetValidDataURLPrefixes() []string {
	return []string{
		"data:application/vc+jwt,",
		"data:application/vc+sd-jwt,",
		"data:application/vc+cose;base64,",
		"data:application/vp+jwt,",
		"data:application/vp+sd-jwt,",
		"data:application/vp+cose;base64,",
	}
}

// ValidateVerifiableCredentials checks that each item in the verifiableCredential array
// in a Verifiable Presentation has the required type and a valid data-url id prefix.
func ValidateVerifiableCredentials(creds []credential.VerifiableCredential) error {
	for _, cred := range creds {
		// Check required types
		hasRequiredType := false
		for _, t := range cred.Type {
			if t == credential.EnvelopedVerifiableCredentialType || t == credential.EnvelopedVerifiablePresentationType {
				hasRequiredType = true
				break
			}
		}
		if !hasRequiredType {
			return fmt.Errorf("verifiableCredential item does not contain required type")
		}

		// Determine which prefix is matched
		matchedPrefix := ""
		for _, prefix := range GetValidDataURLPrefixes() {
			if strings.HasPrefix(cred.ID, prefix) {
				matchedPrefix = prefix
				break
			}
		}
		if matchedPrefix == "" {
			return fmt.Errorf("verifiableCredential item ID does not start with an allowed data-url prefix")
		}

		// Extract the encoded data after the prefix
		encodedData := strings.TrimPrefix(cred.ID, matchedPrefix)

		// Validate the data is well-formed according to its format
		switch {
		case strings.Contains(matchedPrefix, "+jwt"):
			if _, err := jws.Parse([]byte(encodedData)); err != nil {
				return fmt.Errorf("failed to parse JOSE content from data-url: %w", err)
			}
		case strings.Contains(matchedPrefix, "+sd-jwt"):
			if _, err := sdjwt.New(encodedData); err != nil {
				return fmt.Errorf("failed to parse SD-JWT content from data-url: %w", err)
			}
		case strings.Contains(matchedPrefix, "+cose"):
			decodedCBOR, err := base64.RawStdEncoding.DecodeString(encodedData)
			if err != nil {
				return fmt.Errorf("failed to decode base64 content from data-url: %w", err)
			}
			var message cose.Sign1Message
			if err = message.UnmarshalCBOR(decodedCBOR); err != nil {
				return fmt.Errorf("failed to parse COSE content from data-url: %w", err)
			}
		default:
			return fmt.Errorf("unsupported content type in data-url prefix")
		}
	}

	return nil
}
