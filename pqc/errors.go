package pqc

import "errors"

var (
	// ErrAlgorithmRequired is returned when the algorithm name is empty.
	ErrAlgorithmRequired = errors.New("algorithm is required")
	// ErrInvalidKeyLength is returned when a key is not the size required by alg.
	ErrInvalidKeyLength = errors.New("invalid key length")
	// ErrSignerCleaned is returned when Sign is called after Clean.
	ErrSignerCleaned = errors.New("signer has been cleaned")
	// ErrContextUnsupported is returned when a non-empty context string is used
	// with an algorithm that does not support it.
	ErrContextUnsupported = errors.New("algorithm does not support a context string")
)
