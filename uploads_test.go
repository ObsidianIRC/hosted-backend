package main

import "testing"

func TestDetectAndValidateEncryptedAttachment(t *testing.T) {
	payload := append(append([]byte{}, e2eeMagic...), 0x3f, 0xa1, 0x7c, 0x02)

	if err := detectAndValidate(payload, e2eeExtension); err != nil {
		t.Fatalf("magic-prefixed payload rejected: %v", err)
	}

	// Without the header the extension would accept any binary at all, which
	// is what keeps the filehost from becoming a general-purpose dump.
	arbitrary := []byte("MZ\x90\x00\x03\x00\x00\x00")
	if err := detectAndValidate(arbitrary, e2eeExtension); err == nil {
		t.Fatal("payload without the magic header was accepted")
	}
}

func TestEncryptedAttachmentIsNotImageProcessed(t *testing.T) {
	mc := loadMediaConfig(1 << 20)
	if !mc.IsAllowed(e2eeExtension) {
		t.Fatalf("%s missing from the default allowlist", e2eeExtension)
	}
	// The image pipeline re-encodes what it touches, which would break the
	// client's authentication tag.
	if got := mc.Kind(e2eeExtension); got != "other" {
		t.Fatalf("Kind(%s) = %q, want \"other\"", e2eeExtension, got)
	}
}
