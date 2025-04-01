package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"math/big"
)

var keyMask *big.Int
var ksnMask *big.Int

func main() {

	keyMask, _ = new(big.Int).SetString("C0C0C0C000000000C0C0C0C000000000", 16)

	ksnMask, _ = new(big.Int).SetString("FFFFFFFFFFFFFFE00000", 16)

	bdk, _ := new(big.Int).SetString("0123456789ABCDEFFEDCBA9876543210", 16)

	ksn, _ := new(big.Int).SetString("88888851400018400003", 16)

	ipek := createIPEK(*bdk, *ksn)
	dek := createDigitalKey(ipek, *ksn)

	plaintext, _ := new(big.Int).SetString("4111111111111111D301244455556660", 16)

	plaintextTLV := createTLV57(plaintext)

	plaintextPadded := padPKCS7BigInt(plaintextTLV, des.BlockSize)

	plaintextPaddedTLV := updateTLV57(plaintextPadded)

	ciphertext := new(big.Int).SetBytes(tripleDesEncrypt(dek.Bytes(), plaintextPaddedTLV.Bytes()))

	ciphertextTLV := createTLV57(ciphertext)

	fmt.Printf("ciphertext: %x\n", ciphertextTLV)

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

func createDigitalKey(ipek, ksn big.Int) big.Int {
	digitalKeyMask, _ := new(big.Int).SetString("0000000000FF00000000000000FF0000", 16)

	// Derive the base key
	key := deriveKey(ipek, ksn)

	key.Xor(&key, digitalKeyMask)

	leftMask, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFF0000000000000000", 16)
	leftKey := new(big.Int).And(&key, leftMask)
	leftKey.Rsh(leftKey, 64)

	rightMask, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFF", 16)
	rightKey := new(big.Int).And(&key, rightMask)

	cipherTextLeft := new(big.Int).SetBytes(tripleDesEncrypt(key.Bytes(), leftKey.Bytes()))
	cipherTextLeft.Lsh(cipherTextLeft, 64)
	cipherTextRight := new(big.Int).SetBytes(tripleDesEncrypt(key.Bytes(), rightKey.Bytes()))

	result := new(big.Int).Or(cipherTextLeft, cipherTextRight)

	return *result

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

	// tripleDESResult := new(big.Int).SetBytes(desEncrypt(keyLeft.Bytes(), keyReg.Bytes()))
	tripleDESResult := new(big.Int).SetBytes(tripleDesEncrypt(keyLeft.Bytes(), keyReg.Bytes()))

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

func padPKCS7BigInt(data *big.Int, blockSize int) *big.Int {
	// Convert the big.Int to a byte slice
	dataBytes := data.Bytes()

	// Calculate the padding length
	padding := blockSize - len(dataBytes)%blockSize

	// Create the padding bytes
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	// Append the padding to the data
	paddedBytes := append(dataBytes, padtext...)

	// Convert the padded byte slice back to a big.Int
	paddedBigInt := new(big.Int).SetBytes(paddedBytes)

	return paddedBigInt
}

func createTLV57(plaintext *big.Int) *big.Int {
	// Convert the big.Int to a byte slice
	plaintextBytes := plaintext.Bytes()

	// Calculate the length in bytes
	lengthInBytes := len(plaintextBytes)

	// Construct the TLV as a byte slice
	tlvBytes := append([]byte{0x57, byte(lengthInBytes)}, plaintextBytes...)

	// Convert the TLV byte slice back to a big.Int
	tlvBigInt := new(big.Int).SetBytes(tlvBytes)

	return tlvBigInt
}

func updateTLV57(tlv *big.Int) *big.Int {
	// Convert the TLV big.Int to a byte slice
	tlvBytes := tlv.Bytes()

	// Ensure the TLV has at least a tag and length (minimum 2 bytes)
	if len(tlvBytes) < 2 {
		panic("Invalid TLV: too short to contain a tag and length")
	}

	// Extract the value portion of the TLV (everything after the first 2 bytes)
	valueBytes := tlvBytes[2:]

	// Recalculate the length of the value
	lengthInBytes := len(valueBytes)

	// Construct the updated TLV as a byte slice
	updatedTLVBytes := append([]byte{0x57, byte(lengthInBytes)}, valueBytes...)

	// Convert the updated TLV byte slice back to a big.Int
	updatedTLV := new(big.Int).SetBytes(updatedTLVBytes)

	return updatedTLV
}
