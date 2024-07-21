package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type (
	hashType struct {
		Label string
		Hash  func() hash.Hash
	}
)

const Sha1 = "SHA1"
const Sha256 = "SHA256"
const Sha512 = "SHA512"

func ShaSelect(label string) hashType {
	data := []hashType{{
		Label: Sha1,
		Hash:  sha1.New,
	},
		{Label: Sha256, Hash: sha256.New},
		{Label: Sha512,
			Hash: sha512.New}}
	var selected hashType
	for _, v := range data {
		if v.Label == label {
			selected = v
		}
	}
	return selected
}
