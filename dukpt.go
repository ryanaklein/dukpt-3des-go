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

	keyMask = new(big.Int)
	keyMask.SetString("C0C0C0C000000000C0C0C0C000000000", 16)

	ksnMask = new(big.Int)
	ksnMask.SetString("FFFFFFFFFFFFFFE00000", 16)

	bdk := new(big.Int)
	bdk.SetString("0123456789ABCDEFFEDCBA9876543210", 16)

	ksn := new(big.Int)
	ksn.SetString("88888851400018400003", 16)

	ipek := createIPEK(*bdk, *ksn)
	fmt.Printf("ipek: %x\n", &ipek)
	createDigitalKey(ipek, *ksn)

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

func createDigitalKey(ipek, ksn big.Int) {
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

	fmt.Printf("dek: %x\n", result)

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
