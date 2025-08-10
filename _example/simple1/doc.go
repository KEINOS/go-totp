/*
# Simple CLI App of go-totp

This is a simple example usage of [go-totp] package as a CLI app.

	```bash
	cd _example/simple1
	go run main.go
	```

1. PEM text file and PNG image file of the secret will be generated in the current directory.
2. A passcode prompt will be displayed.
3. Open the PNG image and scan the QR code with your authenticator app.
4. Type the passcode to validate it.

	```shellsession
	$ go run main.go
	  - No PEM file/QR code image found. Creating...
	  - PNG image saved to: qr-code.png
	    Please add your TOTP to your OTP Application now!

	Issuer:       Example.com
	Account Name: alice@example.com
	Secret:       YKOF2NNFXYLMB3LN7QVDTHEM3SNLNS26WIQTQTDJVYQ2CMIL46NBXACVZQKTFE2XDERB2PWKQJVSGUSRCNJ25CEZ3DA4MKZQ23Y4PADW45UGZWMY2WXIYRN4MJAFV3LYQBYBR6D37NNQJEFZEKVHKBEYRUXE5VJDC4LJVEMS5KELZVJNACKPG5TTYF7JPYQWW2L2HVKP3OYQM
	Valid Period: 30
	  - Press Ctrl+C to exit.
	    Expect passcode: 366258

	Enter Passcode: 366258
	👍 Passcode is valid!

	  Expect passcode: 366258

	Enter Passcode: 366258
	👍 Passcode is valid!

	  Expect passcode: 366258

	Enter Passcode: 366258
	👎 Passcode is invalid!

	  Expect passcode: 746280

	Enter Passcode: ^Csignal: interrupt
	$
	```

[go-totp]: https://pkg.go.dev/github.com/KEINOS/go-totp/totp
*/
package main
