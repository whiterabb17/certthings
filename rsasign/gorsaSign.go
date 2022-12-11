package rsasign

// Sign using the RSAWithMD5 algorithm
func SignMd5WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignMd5WithRsa(data)
	if err != nil {
		return "", err
	}

	return sign, err
}

// Sign using the RSAWithSHA1 algorithm
func SignSha1WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha1WithRsa(data)
	if err != nil {
		return "", err
	}

	return sign, err
}

// Sign using the RSAWithSHA256 algorithm
func SignSha256WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha256WithRsa(data)
	if err != nil {
		return "", err
	}
	return sign, err
}

// Verify signature using RSAWithMD5
func VerifySignMd5WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignMd5WithRsa(data, signData)
}

// Verify signature using RSAWithSHA1
func VerifySignSha1WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha1WithRsa(data, signData)
}

// Verify signature using RSAWithSHA256
func VerifySignSha256WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha256WithRsa(data, signData)
}
