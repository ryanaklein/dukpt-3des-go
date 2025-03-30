package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"math/big"
)

var keyMask *big.Int
var ksnMask *big.Int

func main() {

	keyMask = new(big.Int)
	keyMask.SetString("C0C0C0C000000000C0C0C0C000000000", 16)

	ksnMask = new(big.Int)
	ksnMask.SetString("FFFFFFFFFFFFFFE00000", 16)

	bdk := new(big.Int)
	bdk.SetString("0123456789ABCDEFFEDCBA9876543210", 16)

	ksn := new(big.Int)
	ksn.SetString("FFFF9876543210E00008", 16)

	ipek := createIPEK(*bdk, *ksn)
	fmt.Printf("ipek: %x\n", &ipek)
	createSessionKey(ipek, *ksn)

}

func createIPEK(bdk, ksn big.Int) big.Int {

	maskedKsn := new(big.Int).And(&ksn, ksnMask)
	shiftedKsn := new(big.Int).Rsh(maskedKsn, 16)

	cipherTextLeft := new(big.Int).SetBytes(tripleDesEncrypt(bdk.Bytes(), shiftedKsn.Bytes()))
	cipherTextLeft.Lsh(cipherTextLeft, 64)

	xOrKey := new(big.Int).Xor(&bdk, keyMask)
	cipherTextRight := new(big.Int).SetBytes(tripleDesEncrypt(xOrKey.Bytes(), shiftedKsn.Bytes()))

	ipek := new(big.Int).Or(cipherTextLeft, cipherTextRight)
	return *ipek

}

func createSessionKey(ipek, ksn big.Int) {

	sessionKeyMask, _ := new(big.Int).SetString("FF00000000000000FF", 16)

	key := deriveKey(ipek, ksn)

	sessionKey := new(big.Int).Xor(&key, sessionKeyMask)

	fmt.Printf("session key: %x\n", sessionKey)

}

func deriveKey(ipek, ksn big.Int) big.Int {

	mask, _ := new(big.Int).SetString("FFFFFFFFFFE00000", 16)
	ksnReg := new(big.Int).And(&ksn, mask)

	currentKey := ipek

	transactionCounterMask := new(big.Int).SetUint64(0x1FFFFF)

	for shiftReg := 0x100000; shiftReg > 0; shiftReg >>= 1 {
		bigShiftReg := new(big.Int).SetUint64(uint64(shiftReg))
		result := new(big.Int).And(bigShiftReg, &ksn)
		result.And(result, transactionCounterMask)
		if result.Cmp(big.NewInt(0)) > 0 {
			ksnReg.Or(ksnReg, bigShiftReg)
			currentKey = generateKey(currentKey, *ksnReg)
		}

	}

	return currentKey

}

func generateKey(key, ksn big.Int) big.Int {

	maskedKey := new(big.Int).Xor(&key, keyMask)

	encryptLeft := encryptRegister(*maskedKey, ksn)
	encryptRight := encryptRegister(key, ksn)

	encryptLeft.Lsh(&encryptLeft, 64)

	result := new(big.Int).Or(&encryptLeft, &encryptRight)
	return *result

}

func encryptRegister(key, reg big.Int) big.Int {

	maskLeft, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFF0000000000000000", 16)
	maskRight, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFF", 16)

	keyLeft := new(big.Int).And(&key, maskLeft)
	keyLeft.Rsh(keyLeft, 64)
	keyRight := new(big.Int).And(&key, maskRight)

	keyReg := new(big.Int).Xor(keyRight, &reg)

	tripleDESResult := new(big.Int).SetBytes(desEncrypt(keyLeft.Bytes(), keyReg.Bytes()))
	// tripleDESResult := tripleDesEncrypt(keyLeft, keyReg)

	encryptionResult := new(big.Int).Xor(keyRight, tripleDESResult)

	return *encryptionResult

}

func tripleDesEncrypt(key, plaintext []byte) []byte {

	if len(plaintext)%des.BlockSize != 0 {
		plaintext = padPKCS7(plaintext, des.BlockSize)
	}

	var tripleDESKey []byte

	if len(key) == 8 {
		tripleDESKey = append(append(key, key...), key...)
	}

	if len(key) == 16 {
		tripleDESKey = append(tripleDESKey, key...)
		tripleDESKey = append(tripleDESKey, key[:8]...)
	}

	block, err := des.NewTripleDESCipher(tripleDESKey)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}

func desEncrypt(key, plaintext []byte) []byte {

	if len(plaintext)%des.BlockSize != 0 {
		plaintext = padPKCS7(plaintext, des.BlockSize)
	}

	// var tripleDESKey []byte
	// tripleDESKey = append(tripleDESKey, key...)
	// tripleDESKey = append(tripleDESKey, key[:8]...)

	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}

func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func bitwiseAndBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("input slices must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] & b[i]
	}
	return result, nil
}

func bitwiseOrBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("input slices must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] | b[i]
	}
	return result, nil
}

func bitwiseXorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("input slices must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func bitwiseNotBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = ^data[i]
	}
	return result
}

func leftShiftBytes(data []byte, shift uint) []byte {
	if shift == 0 || len(data) == 0 {
		return data
	}

	// Create a new slice to store the result
	result := make([]byte, len(data))

	// Calculate the byte and bit shifts
	byteShift := int(shift / 8) // Number of whole bytes to shift
	bitShift := shift % 8       // Number of bits to shift within a byte

	for i := 0; i < len(data); i++ {
		if i+byteShift < len(data) {
			// Shift current byte by bitShift and add overflow from the next byte
			result[i] = data[i+byteShift] << bitShift
			if i+byteShift+1 < len(data) && bitShift > 0 {
				result[i] |= data[i+byteShift+1] >> (8 - bitShift)
			}
		}
	}

	return result
}

func rightShiftBytes(data []byte, shift uint) []byte {
	if shift == 0 || len(data) == 0 {
		return data
	}

	result := make([]byte, len(data))
	byteShift := int(shift / 8)
	bitShift := shift % 8

	for i := len(data) - 1; i >= 0; i-- {
		if i-byteShift >= 0 {
			result[i] = data[i-byteShift] >> bitShift
			if i-byteShift-1 >= 0 && bitShift > 0 {
				result[i] |= data[i-byteShift-1] << (8 - bitShift)
			}
		}
	}
	return result
}

func trimLeadingZeros(data []byte) []byte {
	for i, b := range data {
		if b != 0x00 { // Find the first non-zero byte
			return data[i:] // Slice from the first non-zero byte onward
		}
	}
	return []byte{} // Return an empty slice if all bytes are zero
}

func extractTransactionCounter(ksn []byte) uint32 {
	// Ensure the KSN is at least 3 bytes long
	if len(ksn) < 3 {
		panic("KSN must be at least 3 bytes long")
	}

	// The transaction counter is in the last 20 bits (3 bytes)
	// Mask out the upper 4 bits of the first byte of the last 3 bytes
	return uint32(ksn[len(ksn)-3]&0x1F)<<16 | // Mask upper 4 bits and shift to the most significant position
		uint32(ksn[len(ksn)-2])<<8 | // Take the middle byte and shift it
		uint32(ksn[len(ksn)-1]) // Add the least significant byte
}

func uint32To10ByteSlice(value uint32) []byte {
	// Create a 10-byte slice initialized to zeros
	result := make([]byte, 10)

	// Convert the uint32 value to 4 bytes in big-endian order
	binary.BigEndian.PutUint32(result[6:], value)

	// Return the resulting 10-byte slice
	return result
}

func repeatBytesTo16(key []byte) []byte {
	if len(key) != 8 {
		panic("Key must be 8 bytes long")
	}

	// Duplicate the 8-byte slice to make it 16 bytes
	repeatedKey := append(key, key...)

	return repeatedKey
}
