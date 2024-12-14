package cid

import (
	"embed"
	"github.com/decentralgabe/vc-jose-cose-go/credential"
	"github.com/decentralgabe/vc-jose-cose-go/jose"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

const (
	VMExample1 string = "vm-ed25519.json"
	VMExample2 string = "vm-p256.json"
	VMExample3 string = "vm-p384.json"
	VMExample4 string = "vm-p521.json"
)

var (
	//go:embed testdata
	testVectors   embed.FS
	vmTestVectors = []string{VMExample1, VMExample2, VMExample3, VMExample4}
)

func TestVMVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range vmTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var vm VerificationMethod
		err = json.Unmarshal([]byte(gotTestVector), &vm)
		assert.NoError(t, err)

		vmBytes, err := json.Marshal(vm)
		assert.NoError(t, err)
		assert.JSONEq(t, gotTestVector, string(vmBytes))
	}
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}

func TestBadMediaTypeCred(t *testing.T) {
	vc := `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "http://university.example/credentials/1872",
  "type": [
    "VerifiableCredential",
    "ExampleAlumniCredential"
  ],
  "issuer": "https://example.issuer/vc-jose-cose",
  "validFrom": "2010-01-01T19:23:24Z",
  "credentialSchema": {
    "id": "https://example.org/examples/degree.json",
    "type": "JsonSchema"
  },
  "credentialSubject": {
    "id": "did:example:123",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}`
	var cred credential.VerifiableCredential
	err := json.Unmarshal([]byte(vc), &cred)
	require.NoError(t, err)

	gotTestVector, err := getTestVector(VMExample1)
	require.NoError(t, err)

	var vm VerificationMethod
	err = json.Unmarshal([]byte(gotTestVector), &vm)
	assert.NoError(t, err)

	signed, err := jose.SignVerifiableCredential(cred, vm.SecretKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	println(*signed)
}

func TestBadMediaTypePres(t *testing.T) {
	vp := `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": ["VerifiablePresentation"],
  "holder": "https://example.issuer/vc-jose-cose",
  "verifiableCredential": [{
    "@context": "https://www.w3.org/ns/credentials/v2",
    "type": "EnvelopedVerifiableCredential",
    "id": "data:application/vc+jwt,yJraWQiOiJFeEhrQk1XOWZtYmt2VjI2Nm1ScHVQMnNVWV9OX0VXSU4xbGFwVXpPOHJvIiwiYWxnIjoiRVMyNTYifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaWQiOiJodHRwOi8vdW5pdmVyc2l0eS5leGFtcGxlL2NyZWRlbnRpYWxzLzE4NzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRXhhbXBsZUFsdW1uaUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly91bml2ZXJzaXR5LmV4YW1wbGUvaXNzdWVycy81NjUwNDkiLCJ2YWxpZEZyb20iOiIyMDEwLTAxLTAxVDE5OjIzOjI0WiIsImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL2V4YW1wbGVzL2RlZ3JlZS5qc29uIiwidHlwZSI6Ikpzb25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19.B5Nb-yK8uVEI0292vZqtAcFvJHY2Q-8QaD2eEhg0zrMQ1JlmTAn-FPr761PbFKE1kHMqz7TAeuGVsCA7RXstVA"
  }]
}`
	var pres credential.VerifiablePresentation
	err := json.Unmarshal([]byte(vp), &pres)
	require.NoError(t, err)

	gotTestVector, err := getTestVector(VMExample1)
	require.NoError(t, err)

	var vm VerificationMethod
	err = json.Unmarshal([]byte(gotTestVector), &vm)
	assert.NoError(t, err)

	signed, err := jose.SignVerifiablePresentation(pres, vm.SecretKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	println(*signed)
}
