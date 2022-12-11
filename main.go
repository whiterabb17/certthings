package main

// This package is used to generate Private/Public key files and test
// Encryption and Decryption

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/whiterabb17/certthings/rsa"
	"github.com/whiterabb17/certthings/rsasign"
)

var (
	pubkeyFileName, privKeyFileName string
	keySize                         int
	encryptedStr, decryptedStr      string
)

func exportKeys() error {
	err := rsa.ExportRSAKeysToFile(privKeyFileName, pubkeyFileName, keySize)
	if err != nil {
		return err
	}
	return nil
}

func readFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func getInput(def string) string {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	if line == "" {
		return def
	}
	return line
}

func runTests(privKey string, pubKey string) {
	fmt.Printf("Please enter a string to test encryption with (Default: %s)", "RSA Cert Verification")
	testString := getInput("RSA Cert Verification")
	log.Println("Testing Key Files, please wait...")
	log.Println("Test string: " + testString)

	// --- Encrypt string using Private key & Decrypt using Public key
	// ------ Private key encryption
	encryptedStr, err := rsasign.ApplyPrivateKeyEncryption(testString, privKey)
	if err != nil {
		log.Println("Private key Encryption error: " + err.Error())
	} else {
		log.Println("Private Key Encryption was successful")
		log.Println("Encrypted string: " + encryptedStr)
	}
	// ------ Public key decryption
	decryptedStr, err = rsasign.ApplyPublicKeyDecryption(encryptedStr, pubKey)
	if err == nil && decryptedStr == testString {
		log.Println("Public Key Decryption was successful")
		log.Println("Decrypted String: " + decryptedStr)
	} else {
		log.Println("Public Key Decryption error: " + err.Error())
	}

	// --- Encrypt string using Public key & Decrypt using Private key
	// ------ Public key encryption
	encryptedStr, err = rsasign.ApplyPublicKeyEncryption(testString, privKey)
	if err != nil {
		log.Println("Public key Encryption error: " + err.Error())
	} else {
		log.Println("Public Key Encryption was successful")
		log.Println("Encrypted string: " + encryptedStr)
	}
	// ------ Private key decryption
	decryptedStr, err = rsasign.ApplyPrivateKeyDecryption(testString, privKey)
	if err != nil {
		log.Println("Private key Encryption error: " + err.Error())
	} else {
		log.Println("Private Key Decryption was successful")
		log.Println("Decrypted String: " + decryptedStr)
	}
}

func main() {
	flag.StringVar(&privKeyFileName, "priv", "", " Name of the Private key to create")
	flag.StringVar(&pubkeyFileName, "pub", "", " Name of the Public key to create")
	flag.IntVar(&keySize, "b", 4096, " Key Length (2048/4096)")
	err := exportKeys()
	if err != nil {
		log.Println("Error: " + err.Error())
	} else {
		log.Println("RSA Key Generation was successful")
	}

	fmt.Printf("Would you like to test generated files? (%s,%s)", "y", "n")
	test := getInput("y")
	if test == "y" {
		privKey, _ := readFile(privKeyFileName)
		pubKey, _ := readFile(pubkeyFileName)
		runTests(privKey, pubKey)
	}

}
