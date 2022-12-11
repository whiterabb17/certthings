package rsasign

// --- Private Key Encrypt & Decrypt
func ApplyPrivateKeyEncryption(plain string, privkey string) (string, error) {
	encrypted, err := PriKeyEncrypt(plain, privkey)
	if err != nil {
		return "", err
	}
	return encrypted, err
}
func ApplyPrivateKeyDecryption(encrypted string, privkey string) (string, error) {
	decrypted, err := PriKeyDecrypt(encrypted, privkey)
	if err != nil {
		return "", err
	}
	return decrypted, err
}

// --- Private Key Encrypt & Decrypt
func ApplyPublicKeyEncryption(plain string, pubkey string) (string, error) {
	encrypted, err := PublicEncrypt(plain, pubkey)
	if err != nil {
		return "", err
	}
	return encrypted, err
}
func ApplyPublicKeyDecryption(encrypted string, pubkey string) (string, error) {
	decrypted, err := PublicDecrypt(encrypted, pubkey)
	if err != nil {
		return "", err
	}
	return decrypted, err
}
