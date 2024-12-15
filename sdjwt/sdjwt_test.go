package sdjwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/decentralgabe/vc-jose-cose-go/credential"
	"github.com/decentralgabe/vc-jose-cose-go/util"
)

func Test_Sign_Verify_VerifiableCredential(t *testing.T) {
	simpleVC := credential.VerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		ID:        "https://example.edu/credentials/1872",
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		},
	}

	detailVC := credential.VerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		ID:        "https://example.edu/credentials/1872",
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"address": map[string]any{
				"streetAddress": "123 Main St",
				"city":          "Anytown",
				"country":       "US",
			},
			"details": []any{
				"Detail 1",
				"Detail 2",
			},
		},
	}

	tests := []struct {
		name            string
		curve           jwa.EllipticCurveAlgorithm
		disclosurePaths []DisclosurePath
		vc              *credential.VerifiableCredential
		verifyFields    func(*testing.T, *credential.VerifiableCredential)
	}{
		{
			name:  "EC P-256 with simple credential subject disclosure",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "EC P-256 with complex nested disclosures",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
				"credentialSubject.address.streetAddress",
				"credentialSubject.details[0]",
			},
			vc: &detailVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
				address := vc.CredentialSubject["address"].(map[string]any)
				assert.Equal(t, "123 Main St", address["streetAddress"])
				assert.Equal(t, "Anytown", address["city"])
				details := vc.CredentialSubject["details"].([]any)
				assert.Equal(t, "Detail 1", details[0])
			},
		},
		{
			name:  "EC P-256 with top level disclosures",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"id",
				"validFrom",
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "https://example.edu/credentials/1872", vc.ID)
				assert.Equal(t, "2010-01-01T19:23:24Z", vc.ValidFrom)
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "EC P-384 with simple credential subject disclosure",
			curve: jwa.P384,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "EC P-384 with complex nested disclosures",
			curve: jwa.P384,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
				"credentialSubject.address.streetAddress",
				"credentialSubject.details[0]",
			},
			vc: &detailVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
				address := vc.CredentialSubject["address"].(map[string]any)
				assert.Equal(t, "123 Main St", address["streetAddress"])
				assert.Equal(t, "Anytown", address["city"])
				details := vc.CredentialSubject["details"].([]any)
				assert.Equal(t, "Detail 1", details[0])
			},
		},
		{
			name:  "EC P-384 with top level disclosures",
			curve: jwa.P384,
			disclosurePaths: []DisclosurePath{
				"id",
				"validFrom",
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "https://example.edu/credentials/1872", vc.ID)
				assert.Equal(t, "2010-01-01T19:23:24Z", vc.ValidFrom)
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "EC P-521 with simple credential subject disclosure",
			curve: jwa.P521,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "EC P-521 with complex nested disclosures",
			curve: jwa.P521,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
				"credentialSubject.address.streetAddress",
				"credentialSubject.details[0]",
			},
			vc: &detailVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
				address := vc.CredentialSubject["address"].(map[string]any)
				assert.Equal(t, "123 Main St", address["streetAddress"])
				assert.Equal(t, "Anytown", address["city"])
				details := vc.CredentialSubject["details"].([]any)
				assert.Equal(t, "Detail 1", details[0])
			},
		},
		{
			name:  "EC P-521 with top level disclosures",
			curve: jwa.P521,
			disclosurePaths: []DisclosurePath{
				"id",
				"validFrom",
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "https://example.edu/credentials/1872", vc.ID)
				assert.Equal(t, "2010-01-01T19:23:24Z", vc.ValidFrom)
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "OKP EdDSA with simple credential subject disclosure",
			curve: jwa.Ed25519,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "OKP EdDSA with complex nested disclosures",
			curve: jwa.Ed25519,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
				"credentialSubject.address.streetAddress",
				"credentialSubject.details[0]",
			},
			vc: &detailVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
				address := vc.CredentialSubject["address"].(map[string]any)
				assert.Equal(t, "123 Main St", address["streetAddress"])
				assert.Equal(t, "Anytown", address["city"])
				details := vc.CredentialSubject["details"].([]any)
				assert.Equal(t, "Detail 1", details[0])
			},
		},
		{
			name:  "OKP EdDSA with top level disclosures",
			curve: jwa.Ed25519,
			disclosurePaths: []DisclosurePath{
				"id",
				"validFrom",
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "https://example.edu/credentials/1872", vc.ID)
				assert.Equal(t, "2010-01-01T19:23:24Z", vc.ValidFrom)
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate issuer key
			issuerKey, err := util.GenerateJWK(tt.curve)
			require.NoError(t, err)

			// Sign the credential
			sdJWT, err := SignVerifiableCredential(*tt.vc, tt.disclosurePaths, issuerKey)
			require.NoError(t, err)
			require.NotNil(t, sdJWT)

			// Verify the credential
			verifiedVC, err := VerifyVerifiableCredential(*sdJWT, issuerKey)
			require.NoError(t, err)
			require.NotNil(t, verifiedVC)

			// Verify standard fields
			assert.Equal(t, tt.vc.Context, verifiedVC.Context)
			assert.Equal(t, tt.vc.Type, verifiedVC.Type)
			assert.Equal(t, tt.vc.Issuer, verifiedVC.Issuer)

			// Apply any test-specific verification
			if tt.verifyFields != nil {
				tt.verifyFields(t, verifiedVC)
			}

			// Verify validation fails with wrong key
			wrongKey, err := util.GenerateJWK(tt.curve)
			require.NoError(t, err)
			_, err = VerifyVerifiableCredential(*sdJWT, wrongKey)
			assert.Error(t, err)
		})
	}
}

func Test_Sign_Verify_VerifiablePresentation(t *testing.T) {
	simpleVP := credential.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		Type:    []string{"VerifiablePresentation"},
		Holder:  credential.NewIssuerHolderFromString("did:example:holder"),
		VerifiableCredential: []credential.VerifiableCredential{
			{
				Context: []string{"https://www.w3.org/2018/credentials/v1"},
				Type:    []string{"EnvelopedVerifiableCredential"},
				ID:      "data:application/vc+jwt,eyJhbGciOiJFUzI1NiIsImN0eSI6InZjIiwia2lkIjoiNzN2b01YRk5tTmxPRXB1WUNTSmxoOGVOMGRzY3lrb082Z0J1a2dSUzF1VSIsInR5cCI6InZjK2p3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZXMvZGVncmVlLmpzb24iLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwiaWQiOiJkaWQ6ZXhhbXBsZToxMjMifSwiaWF0IjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJpZCI6Imh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMTg3MiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5pc3N1ZXIvdmMtam9zZS1jb3NlIiwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmlzc3Vlci92Yy1qb3NlLWNvc2UiLCJqdGkiOiJodHRwOi8vdW5pdmVyc2l0eS5leGFtcGxlL2NyZWRlbnRpYWxzLzE4NzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRXhhbXBsZUFsdW1uaUNyZWRlbnRpYWwiXSwidmFsaWRGcm9tIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoifQ.-X6A--TnCgeepna-dXn7j6_q2DfQzjiYdEc-pbaHR38JUIv5ubhjYp2Tb_LJuJInzI7qKfP-JcMlHdd6bDnOLw",
			},
		},
	}

	tests := []struct {
		name            string
		curve           jwa.EllipticCurveAlgorithm
		disclosurePaths []DisclosurePath
		vp              *credential.VerifiablePresentation
		verifyFields    func(*testing.T, *credential.VerifiablePresentation)
	}{
		{
			name:  "EC P-256 with simple presentation disclosure",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"type",
				"verifiableCredential[0].id",
			},
			vp: &simpleVP,
			verifyFields: func(t *testing.T, vp *credential.VerifiablePresentation) {
				assert.Contains(t, vp.Type, "VerifiablePresentation")
				assert.Len(t, vp.VerifiableCredential, 1)
				assert.Contains(t, vp.VerifiableCredential[0].ID, "data:application/vc+jwt,")
			},
		},
		{
			name:  "EC P-384 with simple presentation disclosure",
			curve: jwa.P384,
			disclosurePaths: []DisclosurePath{
				"id",
				"verifiableCredential[0].type",
			},
			vp: &simpleVP,
			verifyFields: func(t *testing.T, vp *credential.VerifiablePresentation) {
				assert.Equal(t, vp.ID, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")
				assert.Len(t, vp.VerifiableCredential, 1)
				assert.Contains(t, vp.VerifiableCredential[0].Type, "EnvelopedVerifiableCredential")
			},
		},
		{
			name:  "EC P-521 with simple presentation disclosure",
			curve: jwa.P521,
			disclosurePaths: []DisclosurePath{
				"holder",
				"verifiableCredential[0].id",
			},
			vp: &simpleVP,
			verifyFields: func(t *testing.T, vp *credential.VerifiablePresentation) {
				assert.Equal(t, vp.Holder.ID(), "did:example:holder")
				assert.Len(t, vp.VerifiableCredential, 1)
				assert.Contains(t, vp.VerifiableCredential[0].ID, "data:application/vc+jwt,")
			},
		},
		{
			name:  "OKP EdDSA with simple presentation disclosure",
			curve: jwa.Ed25519,
			disclosurePaths: []DisclosurePath{
				"type",
				"verifiableCredential[0].id",
			},
			vp: &simpleVP,
			verifyFields: func(t *testing.T, vp *credential.VerifiablePresentation) {
				assert.Contains(t, vp.Type, "VerifiablePresentation")
				assert.Len(t, vp.VerifiableCredential, 1)
				assert.Contains(t, vp.VerifiableCredential[0].ID, "data:application/vc+jwt,")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate holder key
			holderKey, err := util.GenerateJWK(tt.curve)
			require.NoError(t, err)

			// Sign the presentation
			sdJWT, err := SignVerifiablePresentation(*tt.vp, tt.disclosurePaths, holderKey)
			require.NoError(t, err)
			require.NotNil(t, sdJWT)

			// Verify the presentation
			verifiedVP, err := VerifyVerifiablePresentation(*sdJWT, holderKey)
			require.NoError(t, err)
			require.NotNil(t, verifiedVP)

			// Verify standard fields
			assert.Equal(t, tt.vp.Context, verifiedVP.Context)
			assert.Equal(t, tt.vp.Type, verifiedVP.Type)
			assert.Equal(t, tt.vp.Holder, verifiedVP.Holder)

			// Apply any test-specific verification
			if tt.verifyFields != nil {
				tt.verifyFields(t, verifiedVP)
			}

			// Verify validation fails with wrong key
			wrongKey, err := util.GenerateJWK(tt.curve)
			require.NoError(t, err)
			_, err = VerifyVerifiablePresentation(*sdJWT, wrongKey)
			assert.Error(t, err)
		})
	}
}
