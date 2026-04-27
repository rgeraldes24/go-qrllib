package falcon_test

import (
	"log"

	falcon "github.com/theQRL/go-qrllib/crypto/falcon_1024"
)

func Example() {
	pub, priv, err := falcon.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")

	sig, err := priv.Sign(nil, msg)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := falcon.Verify(sig, pub, msg)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		log.Fatal("invalid signature")
	}
}
