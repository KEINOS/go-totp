package main

import (
	"github.com/KEINOS/go-totp/totp"
	"github.com/pkg/errors"

	"bufio"
	"fmt"
	"os"
)

// ----------------------------------------------------------------------------
//  Constants
// ----------------------------------------------------------------------------

const (
	// Issuer is the name of the service that created the TOTP secret.
	Issuer = "Example.com"
	// AccountName is the name of the account that the TOTP secret is for.
	AccountName = "alice@example.com"
	// NameFilePEM is the name of the file to save the PEM encoded secret to.
	NameFilePEM = "secret.pem"
	// NameFileQRCode is the name of the file to save the QR code image.
	NameFileQRCode = "qr-code.png"
	// FixLevel is set to the error correction level as default.
	FixLevel = totp.FixLevelDefault
	// FilePerm is the permissions for the QR code image and PEM file (owner only).
	FilePerm = 0o600
	// ImageWidth is the width of the QR code image.
	ImageWidth = 256
	// ImageHeight is the height of the QR code image.
	ImageHeight = 256
)

// ----------------------------------------------------------------------------
//  Main
// ----------------------------------------------------------------------------

func main() {
	var (
		key *totp.Key
		err error
	)

	if fileExists(NameFilePEM) && fileExists(NameFileQRCode) {
		fmt.Println("- PEM file already exists. Loading...")

		pemStr, err := os.ReadFile(NameFilePEM)
		exitOnError(err)

		key, err = totp.GenKeyFromPEM(string(pemStr))
		exitOnError(err)
	} else {
		fmt.Println("- No PEM file/QR code image found. Creating...")
		key, err = createKeyFiles()
		exitOnError(err)
	}

	display(key)
	fmt.Println("- Press Ctrl+C to exit.")

	// Ask for passcode and validate it.
	for {
		passcodeExpect, err := key.PassCode()
		exitOnError(err)

		fmt.Println("  Expect passcode:", passcodeExpect)

		passcodeActual, err := promptForPasscode()
		exitOnError(err)

		if key.Validate(passcodeActual) {
			fmt.Println("👍 Passcode is valid!")
		} else {
			fmt.Println("👎 Passcode is invalid!")
		}
	}
}

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

// It creates a new TOTP key and saves it to a PEM file.
func createFileKey() (*totp.Key, error) {
	keyObj, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate key")
	}

	keyPEM, err := keyObj.PEM()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get PEM encoded key")
	}

	if err = os.WriteFile(NameFilePEM, []byte(keyPEM), FilePerm); err != nil {
		return nil, errors.Wrap(err, "Failed to write PEM encoded key")
	}

	return keyObj, nil
}

// It saves the QR code image of the TOTP URI to a file.
func createFilePNG(key *totp.Key) error {
	qrCode, err := key.QRCode(FixLevel)
	if err != nil {
		return errors.Wrap(err, "fail to get QR code object")
	}

	imgByte, err := qrCode.PNG(ImageWidth, ImageHeight)
	if err != nil {
		return errors.Wrap(err, "fail to get PNG image")
	}

	if err := os.WriteFile(NameFileQRCode, imgByte, FilePerm); err != nil {
		return errors.Wrap(err, "failed to write PNG image")
	}

	fmt.Println("- PNG image saved to:", NameFileQRCode)
	fmt.Println("  Please add your TOTP to your OTP Application now!")

	return nil
}

// It creates PEM file and QR code image.
func createKeyFiles() (*totp.Key, error) {
	key, err := createFileKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create key file")
	}

	if err := createFilePNG(key); err != nil {
		return nil, errors.Wrap(err, "failed to create QR code image")
	}

	return key, nil
}

func display(key *totp.Key) {
	fmt.Printf("Issuer:       %s\n", key.Options.Issuer)
	fmt.Printf("Account Name: %s\n", key.Options.AccountName)
	fmt.Printf("Secret:       %s\n", key.Secret.Base32())
	fmt.Printf("Valid Period: %d\n", key.Options.Period)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func fileExists(fileName string) bool {
	info, err := os.Stat(fileName)

	// check if error is "file not exists"
	if errors.Is(err, os.ErrNotExist) || (info != nil && info.IsDir()) {
		return false
	}

	return true
}

func promptForPasscode() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Passcode: ")

	text, err := reader.ReadString('\n')
	if err != nil {
		return "", errors.Wrap(err, "failed to read passcode")
	}

	return text, nil
}
