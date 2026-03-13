package ilyacrypto

import (
	"crypto/sha3"
	"os"
)

func DeriveKey(password []byte, salt []byte) [32]byte {
	h := sha3.New256()
	customPrefix := []byte(os.Getenv("ILYA_FUCK_RKN"))
	h.Write(customPrefix)
	h.Write(salt)
	h.Write(password)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}
