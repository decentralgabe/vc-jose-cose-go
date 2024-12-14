package jose

import (
	"errors"
	"fmt"
	"time"

	"github.com/goccy/go-json"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/decentralgabe/vc-jose-cose-go/credential"
)

const (
	VCJOSEType = "vc+jwt"
	VPJOSEType = "vp+jwt"
)

// SignVerifiableCredential dynamically signs a VerifiableCredential based on the key type.
func SignVerifiableCredential(vc credential.VerifiableCredential, key jwk.Key) (*string, error) {
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
	// Convert VC to a map
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

	// Marshal the claims to JSON
	payload, err := json.Marshal(vcMap)
	if err != nil {
		return nil, err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		jws.TypeKey:        VCJOSEType,
		jws.ContentTypeKey: credential.VCContentType,
		jws.AlgorithmKey:   key.Algorithm().String(),
		jws.KeyIDKey:       key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Sign the payload
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	result := string(signed)
	return &result, nil
}

// VerifyVerifiableCredential verifies a VerifiableCredential JWT using the provided key.
func VerifyVerifiableCredential(encodedJWT string, key jwk.Key) (*credential.VerifiableCredential, error) {
	if encodedJWT == "" {
		return nil, errors.New("JWT is required")
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

	// Verify the JWT signature and get the payload
	if _, err := jws.Verify([]byte(encodedJWT), jws.WithKey(key.Algorithm(), key)); err != nil {
		return nil, fmt.Errorf("invalid JWS signature: %w", err)
	}

	// Check expected cty and typ headers
	parsed, err := jws.Parse([]byte(encodedJWT))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS payload: %w", err)
	}
	if len(parsed.Signatures()) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	headers := parsed.Signatures()[0].ProtectedHeaders()
	if typ := headers.Type(); typ != VCJOSEType {
		return nil, fmt.Errorf("unexpected type: %s", typ)
	}
	if cty := headers.ContentType(); cty != credential.VCContentType {
		return nil, fmt.Errorf("unexpected content type: %s", cty)
	}

	// Check that the payload does not contain "vc" or "vp"
	if err := credential.HasVCorVPClaim(parsed.Payload()); err != nil {
		return nil, fmt.Errorf("payload has invalid claims: %w", err)
	}

	// Unmarshal the payload into VerifiableCredential
	vc, err := credential.DecodeVC(parsed.Payload())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiableCredential: %w", err)
	}

	return vc, nil
}

// SignVerifiablePresentation dynamically signs a VerifiablePresentation based on the key type.
func SignVerifiablePresentation(vp credential.VerifiablePresentation, key jwk.Key) (*string, error) {
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

	var alg jwa.SignatureAlgorithm
	kty := key.KeyType()
	switch kty {
	case jwa.EC:
		crv, ok := key.Get(jwk.ECDSACrvKey)
		if !ok || crv == nil {
			return nil, fmt.Errorf("invalid or missing 'crv' parameter")
		}
		crvAlg := crv.(jwa.EllipticCurveAlgorithm)
		switch crvAlg {
		case jwa.P256:
			alg = jwa.ES256
		case jwa.P384:
			alg = jwa.ES384
		case jwa.P521:
			alg = jwa.ES512
		default:
			return nil, fmt.Errorf("unsupported curve: %s", crvAlg.String())
		}
	case jwa.OKP:
		alg = jwa.EdDSA
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	// Convert the VerifiablePresentation to a map for manipulation
	vpMap := make(map[string]any)
	vpBytes, err := json.Marshal(vp)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(vpBytes, &vpMap); err != nil {
		return nil, err
	}

	// Add standard claims
	if !vp.Holder.IsEmpty() {
		vpMap[jwt.IssuerKey] = vp.Holder.ID()
	}
	if vp.ID != "" {
		vpMap[jwt.JwtIDKey] = vp.ID
	}

	vpMap[jwt.IssuedAtKey] = time.Now().Unix()

	// TODO(gabe): allow this to be configurable
	vpMap[jwt.ExpirationKey] = time.Now().Add(time.Hour * 24).Unix()

	// Marshal the claims to JSON
	payload, err := json.Marshal(vpMap)
	if err != nil {
		return nil, err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		jws.TypeKey:        VPJOSEType,
		jws.ContentTypeKey: credential.VPContentType,
		jws.AlgorithmKey:   alg.String(),
		jws.KeyIDKey:       key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Sign the payload
	signed, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	result := string(signed)
	return &result, nil
}

// VerifyVerifiablePresentation verifies a VerifiablePresentation JWT using the provided key.
// TODO(gabe) this does not yet validate signatures of credentials in the presentation
func VerifyVerifiablePresentation(encodedJWT string, key jwk.Key) (*credential.VerifiablePresentation, error) {
	if encodedJWT == "" {
		return nil, errors.New("JWT is required")
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

	// Verify the JWT signature and get the payload
	payload, err := jws.Verify([]byte(encodedJWT), jws.WithKey(key.Algorithm(), key))
	if err != nil {
		return nil, fmt.Errorf("invalid JWS signature: %w", err)
	}

	// Check expected cty and typ headers
	parsed, err := jws.Parse([]byte(encodedJWT))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS payload: %w", err)
	}
	if len(parsed.Signatures()) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	headers := parsed.Signatures()[0].ProtectedHeaders()
	if typ := headers.Type(); typ != VPJOSEType {
		return nil, fmt.Errorf("unexpected type: %s", typ)
	}
	if cty := headers.ContentType(); cty != credential.VPContentType {
		return nil, fmt.Errorf("unexpected content type: %s", cty)
	}

	// Check that the payload does not contain "vc" or "vp"
	if err := credential.HasVCorVPClaim(parsed.Payload()); err != nil {
		return nil, fmt.Errorf("payload has invalid claims: %w", err)
	}

	// Unmarshal the payload into VerifiablePresentation
	vp, err := credential.DecodeVP(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiablePresentation: %w", err)
	}

	return vp, nil
}
