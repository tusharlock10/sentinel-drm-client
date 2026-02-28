package crypto

import (
	"os"
	"testing"
)

func TestBase64URLRoundtrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello world"),
		{0, 1, 2, 255, 254},
		{},
	}
	for _, input := range cases {
		encoded := Base64URLEncode(input)
		decoded, err := Base64URLDecode(encoded)
		if err != nil {
			t.Fatalf("decode error for input %v: %v", input, err)
		}
		if string(decoded) != string(input) {
			t.Fatalf("roundtrip mismatch: got %v, want %v", decoded, input)
		}
	}
}

func TestBase64URLNoPadding(t *testing.T) {
	// Python: base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode() => "aGVsbG8"
	encoded := Base64URLEncode([]byte("hello"))
	if encoded != "aGVsbG8" {
		t.Fatalf("expected aGVsbG8, got %s", encoded)
	}
}

func TestECKeyRoundtrip(t *testing.T) {
	priv, err := GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	privPEM, err := ECPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("private key to PEM: %v", err)
	}
	parsedPriv, err := ParseECPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("parse private key PEM: %v", err)
	}
	if parsedPriv.D.Cmp(priv.D) != 0 {
		t.Fatal("private key D mismatch after roundtrip")
	}

	pubPEM, err := ECPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("public key to PEM: %v", err)
	}
	parsedPub, err := ParseECPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse public key PEM: %v", err)
	}
	if parsedPub.X.Cmp(priv.PublicKey.X) != 0 || parsedPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("public key mismatch after roundtrip")
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	priv, err := GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	data := []byte("test payload for signing")
	sig, err := SignECDSA(priv, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyECDSA(&priv.PublicKey, data, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	priv, _ := GenerateECKeyPair()
	data := []byte("original data")
	sig, _ := SignECDSA(priv, data)

	if err := VerifyECDSA(&priv.PublicKey, []byte("tampered data"), sig); err == nil {
		t.Fatal("expected error for tampered data, got nil")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	priv1, _ := GenerateECKeyPair()
	priv2, _ := GenerateECKeyPair()
	data := []byte("some data")
	sig, _ := SignECDSA(priv1, data)
	if err := VerifyECDSA(&priv2.PublicKey, data, sig); err == nil {
		t.Fatal("expected error when verifying with wrong key, got nil")
	}
}

func TestCanonicalJSONKeyOrdering(t *testing.T) {
	// Python: json.dumps({"z": 1, "a": 2, "m": 3}, sort_keys=True, separators=(",",":"))
	// => '{"a":2,"m":3,"z":1}'
	input := map[string]any{"z": 1, "a": 2, "m": 3}
	out, err := CanonicalJSON(input)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	want := `{"a":2,"m":3,"z":1}`
	if string(out) != want {
		t.Fatalf("expected %s, got %s", want, string(out))
	}
}

func TestCanonicalJSONNestedKeyOrdering(t *testing.T) {
	// Python: json.dumps({"b": {"y": 1, "x": 2}, "a": 0}, sort_keys=True, separators=(",",":"))
	// => '{"a":0,"b":{"x":2,"y":1}}'
	input := map[string]any{
		"b": map[string]any{"y": 1, "x": 2},
		"a": 0,
	}
	out, err := CanonicalJSON(input)
	if err != nil {
		t.Fatalf("canonical json nested: %v", err)
	}
	want := `{"a":0,"b":{"x":2,"y":1}}`
	if string(out) != want {
		t.Fatalf("expected %s, got %s", want, string(out))
	}
}

func TestCanonicalJSONEnsureASCII(t *testing.T) {
	// Python: json.dumps({"k": "héllo"}, sort_keys=True, separators=(",",":"), ensure_ascii=True)
	// => '{"k":"h\u00e9llo"}'
	input := map[string]any{"k": "héllo"}
	out, err := CanonicalJSON(input)
	if err != nil {
		t.Fatalf("canonical json ascii: %v", err)
	}
	want := `{"k":"h\u00e9llo"}`
	if string(out) != want {
		t.Fatalf("expected %s, got %s", want, string(out))
	}
}

func TestCanonicalJSONTypes(t *testing.T) {
	// Verify correct handling of bool, null, array, number.
	// Keys sorted: active, count, items, nil
	input := map[string]any{
		"active": true,
		"count":  float64(42),
		"items":  []any{"b", "a"},
		"nil":    nil,
	}
	out, err := CanonicalJSON(input)
	if err != nil {
		t.Fatalf("canonical json types: %v", err)
	}
	want := `{"active":true,"count":42,"items":["b","a"],"nil":null}`
	if string(out) != want {
		t.Fatalf("expected %s, got %s", want, string(out))
	}
}

func TestSHA256Hex(t *testing.T) {
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	got := SHA256Hex([]byte{})
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("SHA256Hex empty: got %s, want %s", got, want)
	}

	// SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	got2 := SHA256Hex([]byte("hello"))
	want2 := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got2 != want2 {
		t.Fatalf("SHA256Hex hello: got %s, want %s", got2, want2)
	}
}

func TestSHA256File(t *testing.T) {
	content := []byte("file content for checksum test")
	f, err := os.CreateTemp("", "sha256test-*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	got, err := SHA256File(f.Name())
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}
	want := SHA256Hex(content)
	if got != want {
		t.Fatalf("SHA256File mismatch: got %s, want %s", got, want)
	}
}

func TestParseECPublicKeyPEMInvalid(t *testing.T) {
	_, err := ParseECPublicKeyPEM("not a PEM")
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestParseECPrivateKeyPEMInvalid(t *testing.T) {
	_, err := ParseECPrivateKeyPEM([]byte("not a PEM"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}
