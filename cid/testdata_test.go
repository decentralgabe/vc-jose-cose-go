package cid

import (
	"embed"
	"encoding/base64"
	"testing"

	"github.com/decentralgabe/vc-jose-cose-go/cose"
	"github.com/decentralgabe/vc-jose-cose-go/credential"
	"github.com/decentralgabe/vc-jose-cose-go/jose"
	"github.com/stretchr/testify/require"

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

	gotTestVector, err := getTestVector(VMExample2)
	require.NoError(t, err)

	var vm VerificationMethod
	err = json.Unmarshal([]byte(gotTestVector), &vm)
	assert.NoError(t, err)

	signed, err := cose.SignVerifiableCredential(cred, vm.SecretKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	println(base64.RawStdEncoding.EncodeToString(signed))
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
  "verifiableCredential": [
    {
      "@context": "https://www.w3.org/ns/credentials/v2",
      "type": "EnvelopedVerifiableCredential",
      "id": "data:application/vc+jwt,eyJhbGciOiJFUzI1NiIsImN0eSI6InZjIiwia2lkIjoiNzN2b01YRk5tTmxPRXB1WUNTSmxoOGVOMGRzY3lrb082Z0J1a2dSUzF1VSIsInR5cCI6InZjK2p3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZXMvZGVncmVlLmpzb24iLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwiaWQiOiJkaWQ6ZXhhbXBsZToxMjMifSwiaWF0IjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJpZCI6Imh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMTg3MiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5pc3N1ZXIvdmMtam9zZS1jb3NlIiwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmlzc3Vlci92Yy1qb3NlLWNvc2UiLCJqdGkiOiJodHRwOi8vdW5pdmVyc2l0eS5leGFtcGxlL2NyZWRlbnRpYWxzLzE4NzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRXhhbXBsZUFsdW1uaUNyZWRlbnRpYWwiXSwidmFsaWRGcm9tIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoifQ.8MlgeePPgLKmffZriidj8y2Z5rlxX4A7-dDppUMMjNNURUk9PaG6Qh5irW0Gyot1ZITIFPn1in9OZINvB6dkOA"
    },
    {
      "@context": "https://www.w3.org/ns/credentials/v2",
      "type": "EnvelopedVerifiableCredential",
      "id": "data:application/vc+sd-jwt,eyJhbGciOiJFUzM4NCIsImN0eSI6InZjIiwia2lkIjoiOTZxQm5EcHZTNng4WVNDSF94bW5MbFhaTWtEaEhCcjhsajk5dTVhb2c3cyIsInR5cCI6InZjK3NkLWp3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbImtuYzN2Z2pmZlpUUDdwRHk2OVAxVndOV1RGVFhxblg1b0R1Nl9wU2RTYzAiLCIxeElDZkE3Z3VLVXZwU3F6RF9TelhwTU55U1RyWVRDSWNwNEwxOU1YdnFzIl0sImJpcnRoRGF0ZSI6IjE5OTAtMDEtMDEiLCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9LCJpYXQiOiIyMDI0LTAxLTAxVDAwOjAwOjAwWiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5pc3N1ZXIvdmMtam9zZS1jb3NlIiwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmlzc3Vlci92Yy1qb3NlLWNvc2UiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDcmVkZW50aWFsIl0sInZhbGlkRnJvbSI6IjIwMjQtMDEtMDFUMDA6MDA6MDBaIn0.bCgz_EgNH5ELRr-xvudGvtIWMQxobkjKLnQer3iXV3iZk4_vKpMG8hUzvrrWlcpoxJo-Dh_Usm8LYcFOdnCHXdVNlnfz8baLEvNRcUc-60NkEwD739qjbEEvrCnYY9jb~WyI0bUZLME14VEsyRmluZFNxQ0ktSzhBIiwiZmlyc3ROYW1lIiwiSmFuZSJd~WyJvU3lzbndsZ1ZGREUzZzdsbTJKZFZRIiwibGFzdE5hbWUiLCJEb2UiXQ~"
    },
    {
      "@context": "https://www.w3.org/ns/credentials/v2",
      "type": "EnvelopedVerifiableCredential",
      "id": "data:application/vc+cose;base64,0oRYVqQBJgNuYXBwbGljYXRpb24vdmMEWCs3M3ZvTVhGTm1ObE9FcHVZQ1NKbGg4ZU4wZHNjeWtvTzZnQnVrZ1JTMXVVEHNhcHBsaWNhdGlvbi92Yytjb3NloFkB8nsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YyIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFeGFtcGxlQWx1bW5pQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMTg3MiIsImlzc3VlciI6Imh0dHBzOi8vZXhhbXBsZS5pc3N1ZXIvdmMtam9zZS1jb3NlIiwidmFsaWRGcm9tIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwiaWQiOiJkaWQ6ZXhhbXBsZToxMjMifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZXMvZGVncmVlLmpzb24iLCJ0eXBlIjoiSnNvblNjaGVtYSJ9fVhAs3W1WN83yVu/HoEyYMy7Tcmub9zL55PDnfcx5yG42BTe0gdQ+E0V9B3B1gMZyt9dDEGZVJynd8vztWVr7d4Kkw"
    }
  ]
}`
	var pres credential.VerifiablePresentation
	err := json.Unmarshal([]byte(vp), &pres)
	require.NoError(t, err)

	gotTestVector, err := getTestVector(VMExample3)
	require.NoError(t, err)

	var vm VerificationMethod
	err = json.Unmarshal([]byte(gotTestVector), &vm)
	assert.NoError(t, err)

	signed, err := jose.SignVerifiablePresentation(pres, vm.SecretKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	_, err = jose.VerifyVerifiablePresentation(*signed, vm.PublicKeyJWK)
	require.NoError(t, err)
	println(*signed)
}
