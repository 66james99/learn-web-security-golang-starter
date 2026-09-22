package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength                = 128
	argon2idVersion          = 19
	argon2idMemoryKiB        = 19 * 1024
	argon2idIterations       = 2
	argon2idParallelism      = 1
	argon2idSaltLength       = 16
	argon2idDerivedKeyLength = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, argon2idSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derivedKey := argon2.IDKey([]byte(password), salt, argon2idIterations, argon2idMemoryKiB, argon2idParallelism, argon2idDerivedKeyLength)
	return encodeArgon2idHash(argon2idHash{
		version:     argon2idVersion,
		memoryKiB:   argon2idMemoryKiB,
		iterations:  argon2idIterations,
		parallelism: argon2idParallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedHash.version != argon2idVersion {
		return false
	}
	candidateKey := argon2.IDKey([]byte(password), parsedHash.salt, parsedHash.iterations, parsedHash.memoryKiB, parsedHash.parallelism, uint32(len(parsedHash.derivedKey)))
	return subtle.ConstantTimeCompare(candidateKey, parsedHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	return parsedHash.version != argon2idVersion ||
		parsedHash.memoryKiB != argon2idMemoryKiB ||
		parsedHash.iterations != argon2idIterations ||
		parsedHash.parallelism != argon2idParallelism ||
		len(parsedHash.derivedKey) != argon2idDerivedKeyLength
}
