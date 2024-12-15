package sdjwt

import (
	"crypto"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/goccy/go-json"

	sdjwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/decentralgabe/vc-jose-cose-go/credential"
	"github.com/decentralgabe/vc-jose-cose-go/validation"
)

const (
	VCSDJWTType = "vc+sd-jwt"
	VPSDJWTType = "vp+sd-jwt"
)

// DisclosurePath represents a path to a field that should be made selectively disclosable
// Example paths:
// - "credentialSubject.id"
// - "credentialSubject.address.streetAddress"
// - "credentialSubject.nationalities[0]" for array element
type DisclosurePath string

// SignVerifiableCredential creates an SD-JWT from a VerifiableCredential, making specified fields
// selectively disclosable according to the provided paths.
func SignVerifiableCredential(vc credential.VerifiableCredential, disclosurePaths []DisclosurePath, key jwk.Key) (*string, error) {
	if vc.IsEmpty() {
		return nil, errors.New("VerifiableCredential is empty")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Convert VC to a map for manipulation
	vcMap, err := vc.ToMap()
	if err != nil {
		return nil, fmt.Errorf("failed to convert VC to map: %w", err)
	}

	// Add standard claims
	if !vc.Issuer.IsEmpty() {
		vcMap[jwt.IssuerKey] = vc.Issuer.ID()
	}
	if vc.ID != "" {
		vcMap[jwt.JwtIDKey] = vc.ID
	}
	if vc.ValidFrom != "" {
		vcMap[jwt.IssuedAtKey] = vc.ValidFrom
	}
	if vc.ValidUntil != "" {
		vcMap[jwt.ExpirationKey] = vc.ValidUntil
	}

	// Process disclosures
	disclosures := make([]disclosure.Disclosure, 0, len(disclosurePaths))
	processedMap, err := processDisclosures(vcMap, disclosurePaths, &disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to process disclosures: %w", err)
	}
	vcMap = processedMap

	// Marshal the claims to JSON
	payload, err := json.Marshal(vcMap)
	if err != nil {
		return nil, err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		jws.TypeKey:        VCSDJWTType,
		jws.ContentTypeKey: credential.VCContentType,
		jws.AlgorithmKey:   key.Algorithm().String(),
		jws.KeyIDKey:       key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Sign the JWS issuer key
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	// Combine JWT with disclosures
	sdJWTParts := []string{(string)(signed)}
	for _, d := range disclosures {
		sdJWTParts = append(sdJWTParts, d.EncodedValue)
	}

	sdJWT := fmt.Sprintf("%s~", strings.Join(sdJWTParts, "~"))
	return &sdJWT, nil
}

// processDisclosures traverses the credential map and creates disclosures for specified paths
func processDisclosures(data map[string]any, paths []DisclosurePath, disclosures *[]disclosure.Disclosure) (map[string]any, error) {
	result := make(map[string]any)
	for k, v := range data {
		result[k] = v
	}
	for _, path := range paths {
		parts := strings.Split(string(path), ".")
		if err := processPath(result, parts, disclosures); err != nil {
			return nil, fmt.Errorf("failed to process path %s: %w", path, err)
		}
	}
	return result, nil
}

// processPath handles a single disclosure path
func processPath(data map[string]any, pathParts []string, disclosures *[]disclosure.Disclosure) error {
	if len(pathParts) == 0 {
		return nil
	}

	// Split path part into field name and optional array index
	parts := strings.SplitN(pathParts[0], "[", 2)
	field := parts[0]
	arrayIndex := -1

	// Check if we have an array index
	if len(parts) == 2 {
		// Remove trailing ']'
		indexStr := strings.TrimSuffix(parts[1], "]")
		var err error
		arrayIndex, err = strconv.Atoi(indexStr)
		if err != nil {
			return fmt.Errorf("invalid array index '%s' in path: %s", indexStr, pathParts[0])
		}
	}

	value, exists := data[field]
	if !exists {
		return fmt.Errorf("field not found: %s", field)
	}

	// If this is the last path part, create the disclosure
	if len(pathParts) == 1 {
		if arrayIndex >= 0 {
			arr, ok := value.([]any)
			if !ok {
				return fmt.Errorf("field %s is not an array", field)
			}
			if arrayIndex >= len(arr) {
				return fmt.Errorf("array index %d out of bounds for field %s", arrayIndex, field)
			}
			// Create disclosure for array element
			d, err := disclosure.NewFromArrayElement(arr[arrayIndex], nil)
			if err != nil {
				return err
			}
			*disclosures = append(*disclosures, *d)

			// Replace with digest
			arr[arrayIndex] = map[string]any{
				"...": string(d.Hash(crypto.SHA256.New())),
			}
			data[field] = arr
		} else {
			// Create disclosure for object property
			d, err := disclosure.NewFromObject(field, value, nil)
			if err != nil {
				return err
			}
			*disclosures = append(*disclosures, *d)

			// Add hash to _sd array
			hash := d.Hash(crypto.SHA256.New())
			sdPrefix := "_sd"
			if data[sdPrefix] == nil {
				data[sdPrefix] = []string{string(hash)}
			} else {
				data[sdPrefix] = append(data[sdPrefix].([]string), string(hash))
			}
			delete(data, field)
		}
		return nil
	}

	// Need to traverse deeper
	if arrayIndex >= 0 {
		arr, ok := value.([]any)
		if !ok {
			return fmt.Errorf("field %s is not an array", field)
		}
		if arrayIndex >= len(arr) {
			return fmt.Errorf("array index %d out of bounds for field %s", arrayIndex, field)
		}
		nextMap, ok := arr[arrayIndex].(map[string]any)
		if !ok {
			return fmt.Errorf("array element at index %d of field %s is not an object", arrayIndex, field)
		}
		if err := processPath(nextMap, pathParts[1:], disclosures); err != nil {
			return err
		}
		arr[arrayIndex] = nextMap
		data[field] = arr
		return nil
	}

	nextMap, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("field %s is not an object", field)
	}

	return processPath(nextMap, pathParts[1:], disclosures)
}

// VerifyVerifiableCredential verifies an SD-JWT credential and returns the disclosed claims
func VerifyVerifiableCredential(sdJWT string, key jwk.Key) (*credential.VerifiableCredential, error) {
	if sdJWT == "" {
		return nil, errors.New("SD-JWT is required")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Parse and verify the SD-JWT
	sdJWTContainer, err := sdjwt.New(sdJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}

	// Get disclosed claims
	claims, err := sdJWTContainer.GetDisclosedClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosed claims: %w", err)
	}

	// Convert claims back to VerifiableCredential
	vcBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Unmarshal the payload into VerifiableCredential
	vc, err := validation.DecodeVC(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiableCredential: %w", err)
	}

	// Extract signature from SD-JWT
	parts := strings.Split(sdJWT, "~")
	if len(parts) < 1 {
		return nil, errors.New("invalid SD-JWT format")
	}

	plainJWS := parts[0]
	jwsParts := strings.Split(plainJWS, ".")
	if len(jwsParts) != 3 {
		return nil, errors.New("invalid JWS format")
	}

	if _, err = jws.Verify([]byte(plainJWS), jws.WithKey(key.Algorithm(), key)); err != nil {
		return nil, fmt.Errorf("invalid JWS signature: %w", err)
	}

	// Check expected cty and typ headers
	parsed, err := jws.Parse([]byte(plainJWS))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS payload: %w", err)
	}
	if len(parsed.Signatures()) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	headers := parsed.Signatures()[0].ProtectedHeaders()
	if typ := headers.Type(); typ != VCSDJWTType {
		return nil, fmt.Errorf("unexpected type: %s", typ)
	}
	if cty := headers.ContentType(); cty != credential.VCContentType {
		return nil, fmt.Errorf("unexpected content type: %s", cty)
	}

	// Check that the payload does not contain "vc" or "vp"
	if err = validation.HasVCorVPClaim(parsed.Payload()); err != nil {
		return nil, fmt.Errorf("payload has invalid claims: %w", err)
	}

	return vc, nil
}

// SignVerifiablePresentation creates an SD-JWT from a VerifiablePresentation, making specified fields
// selectively disclosable according to the provided paths.
// TODO(gabe) this does not yet validate signatures of credentials in the presentation
func SignVerifiablePresentation(vp credential.VerifiablePresentation, disclosurePaths []DisclosurePath, key jwk.Key) (*string, error) {
	if vp.IsEmpty() {
		return nil, errors.New("VerifiablePresentation is empty")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}
	if len(disclosurePaths) == 0 {
		return nil, errors.New("at least one disclosure path is required")
	}

	// Convert VP to a map for manipulation
	vpMap, err := vp.ToMap()
	if err != nil {
		return nil, fmt.Errorf("failed to convert VP to map: %w", err)
	}

	// Add standard claims
	if vp.ID != "" {
		vpMap[jwt.JwtIDKey] = vp.ID
	}
	if !vp.Holder.IsEmpty() {
		vpMap[jwt.IssuerKey] = vp.Holder.ID()
	}

	// Process disclosures
	disclosures := make([]disclosure.Disclosure, 0, len(disclosurePaths))
	processedMap, err := processDisclosures(vpMap, disclosurePaths, &disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to process disclosures: %w", err)
	}
	vpMap = processedMap

	// Marshal the claims to JSON
	payload, err := json.Marshal(vpMap)
	if err != nil {
		return nil, err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		jws.TypeKey:        VPSDJWTType,
		jws.ContentTypeKey: credential.VPContentType,
		jws.AlgorithmKey:   key.Algorithm().String(),
		jws.KeyIDKey:       key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Sign the JWS with the holder's key
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	// Combine JWT with disclosures
	sdJWTParts := []string{(string)(signed)}
	for _, d := range disclosures {
		sdJWTParts = append(sdJWTParts, d.EncodedValue)
	}

	sdJWT := fmt.Sprintf("%s~", strings.Join(sdJWTParts, "~"))
	return &sdJWT, nil
}

// VerifyVerifiablePresentation verifies an SD-JWT presentation and returns the disclosed claims
func VerifyVerifiablePresentation(sdJWT string, key jwk.Key) (*credential.VerifiablePresentation, error) {
	if sdJWT == "" {
		return nil, errors.New("SD-JWT is required")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Parse and verify the SD-JWT
	sdJWTContainer, err := sdjwt.New(sdJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}

	// Get disclosed claims
	claims, err := sdJWTContainer.GetDisclosedClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosed claims: %w", err)
	}

	// Convert claims back to VerifiablePresentation
	vpBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Unmarshal the payload into VerifiablePresentation
	vp, err := validation.DecodeVP(vpBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiablePresentation: %w", err)
	}

	// Extract signature from SD-JWT
	parts := strings.Split(sdJWT, "~")
	if len(parts) < 1 {
		return nil, errors.New("invalid SD-JWT format")
	}

	plainJWS := parts[0]
	jwsParts := strings.Split(plainJWS, ".")
	if len(jwsParts) != 3 {
		return nil, errors.New("invalid JWS format")
	}

	if _, err = jws.Verify([]byte(plainJWS), jws.WithKey(key.Algorithm(), key)); err != nil {
		return nil, fmt.Errorf("invalid JWS signature: %w", err)
	}

	// Check expected cty and typ headers
	parsed, err := jws.Parse([]byte(plainJWS))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS payload: %w", err)
	}
	if len(parsed.Signatures()) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	headers := parsed.Signatures()[0].ProtectedHeaders()
	if typ := headers.Type(); typ != VPSDJWTType {
		return nil, fmt.Errorf("unexpected type: %s", typ)
	}
	if cty := headers.ContentType(); cty != credential.VPContentType {
		return nil, fmt.Errorf("unexpected content type: %s", cty)
	}

	// Check that the payload does not contain "vc" or "vp"
	if err = validation.HasVCorVPClaim(parsed.Payload()); err != nil {
		return nil, fmt.Errorf("payload has invalid claims: %w", err)
	}

	// Make sure the credentials in the presentation are well-formed
	if len(vp.VerifiableCredential) != 0 {
		if err = validation.ValidateVerifiableCredentials(vp.VerifiableCredential); err != nil {
			return nil, fmt.Errorf("failed to validate Verifiable Credentials in Verifiable Presentation: %w", err)
		}
	}

	return vp, nil
}
