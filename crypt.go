package main

import "log"
import "os"
import "crypto/aes"
import "crypto/cipher"
import "io"
import "fmt"
import "flag"

var source *string = flag.String("s", "", "Source directory or file")
var destination *string = flag.String("d", "", "Destination directory or file")

func main() {

	// Parse the command line options
	flag.Parse()

	Debug("Source:", *source)
	Debug("Destination:", *destination)


	destFile, err := os.Create(*destination)
	defer destFile.Close()
	checkerror(err)

	inFile, err := os.Open(*source)
	defer inFile.Close()
	checkerror(err)

	key := []byte("example key 1234")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// TODO: Think about if using no initialization vector
	// is secure enough. Normally same files and same key
	// should result in the same destination file imho.

	var iv [aes.BlockSize]byte
	stream := cipher.NewCTR(block, iv[:]) // TODO: Check security

	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(destFile, reader); err != nil {
		panic(err)
	}

	Debug("done")


}

func Debug(args ...interface{}) {
	log.Printf("DEBUG %v", args)
}

func Error(args ...interface{}) {
	log.Printf("ERROR %v", args)
}

func checkerror(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}