package main

import (
	// program stuff
	"flag"
	"log"
	"os"
	"path/filepath"
	"fmt"

	// checksums
	"crypto/sha256"
	"io"
	"encoding/hex"
	"bytes"

	// tar and compression
	"archive/tar"
	"compress/gzip"
	"time"

	// encryption
	"crypto/aes"
	"crypto/cipher"
)

var debug *bool = flag.Bool("debug", false, "enable debug logging")
var flagsource *string = flag.String("source", "", "Source directory or file")
var flagdestination *string = flag.String("destination", "", "Destination directory or file")

type File struct {
	PrettyPath string
	Checksum string
}

func main() {

	// Parse the command line options
	flag.Parse()
	Debug("debug:", *debug)
	Debug("flagsource:", *flagsource)
	Debug("flagdestination:", *flagdestination)

	// First element of tail is the action
	if len(flag.Args()) < 1 {
		log.Fatal("Action not specified! See \"", filepath.Base(os.Args[0]), " -h\"")
	}

	action := flag.Args()[0]
	Debug("action:", action)
	Debug("tail:", flag.Args())

	// Choose what is to do
	switch action {
	case "encryptto": //secutran encryptto <dest> <source, source, source>

		// Prepare destination
		destination := normalizePath(flag.Args()[1])
		if PathIsDirectory(destination) {
			destination = destination + "/destFile" // TODO
		}
		if FileExists(destination) {
			//log.Fatal("Destination \"", destination, "\" does already exist. Aborting.") // TODO
		}
		Debug("Final destination:", destination)

		// Prepare sources
		sources := normalizePaths(flag.Args()[2:])
		sources = AddRecursively(sources)
		Debug("Final sources:", sources)

		// Start
		encrypt(sources, destination)

	case "encrypt":
		//secutran encrypt <source, source, source> (dest = workingdir)
		//secutran encrypt --destination=<dest> <source, source, source>

		// Prepare destination
		destination := normalizePath(*flagdestination)
		if destination == "" {
			destination = normalizePath(".")
		}
		if PathIsDirectory(destination) {
			destination = destination + "/destFile" // TODO
		}
		if FileExists(destination) {
			//log.Fatal("Destination \"", destination, "\" does already exist. Aborting.") // TODO
		}
		Debug("Final destination:", destination)

		// Prepare sources
		sources := normalizePaths(flag.Args()[1:])
		sources = AddRecursively(sources)
		Debug("Final sources:", sources)

		// Start
		encrypt(sources, destination)

	case "decryptto":
		//secutran decryptto <dest> <source>
		log.Fatal("NOT IMPLEMENTED YET")

	case "decrypt":
		//secutran decrypt <source> (dest = workingdir)
		//secutran decrypt --destination=<dest> <source>
		log.Fatal("NOT IMPLEMENTED YET")

	default: // TODO: Add actions to usage output
		log.Fatal("Action \"", action, "\" is not valid! See \"", filepath.Base(os.Args[0]), " -h\"")
	}
}

func encrypt(files []string, destination string) {

	Debug("ENCRYPTING")
	Debug("number of files:", len(files))
	Debug("files:", files)
	Debug("destination:", destination)

	// Calculate common prefix for all given files
	commonPath := CommonPrefix(os.PathSeparator, files...)
	if commonPath == "" {
		fmt.Println("No common path")
	} else {
		fmt.Println("Common path:", commonPath)
	}

	// Create map with full and relative file name and checksum
	fileMap := make(map[string]File)

	for _, filename := range files {
		file := File{}
		file.PrettyPath, _ = filepath.Rel(commonPath, filename)
		file.Checksum = calculateChecksum(filename)

		fileMap[filename] = file
	}

	tarfile, err := os.Create(destination)
	defer tarfile.Close()
	checkerror(err)







	key := []byte("example key 1234")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	cryptor := cipher.StreamWriter{S: stream, W: tarfile}


	fileWriter := gzip.NewWriter(cryptor)
	defer fileWriter.Close()

	tarfileWriter := tar.NewWriter(fileWriter)
	defer tarfileWriter.Close()

	for _, filename := range files {

		// Get file info
		fileInfo, err := os.Stat(filename)
		if err != nil {
			log.Fatal("Could not retrieve file info for file ", filename)
		}

		if fileInfo.IsDir() {
			continue
		}

		file, err := os.Open(filename)
		defer file.Close()
		checkerror(err)

		// prepare the tar header

		header := new(tar.Header)
		str, _ := filepath.Rel(commonPath, file.Name())
		header.Name = str
		Debug("file.name:", str)
		header.Size = fileInfo.Size()
		header.Mode = int64(fileInfo.Mode())
		header.ModTime = fileInfo.ModTime()

		err = tarfileWriter.WriteHeader(header)
		checkerror(err)

		_, err = io.Copy(tarfileWriter, file)
		checkerror(err)
	}

	// Create checksumFileString
	checksumFileString := createChecksumString(fileMap)

	// Add file with checksums to tar
	// TODO: Calculation of checksums could be parallelized to tar-creation
	checksumHeader := new(tar.Header)
	checksumHeader.Name = "checksums.sha256"
	checksumHeader.Size = int64(len(checksumFileString))
	checksumHeader.Mode = int64(0644)
	checksumHeader.ModTime = time.Now()

	err = tarfileWriter.WriteHeader(checksumHeader)
	checkerror(err)

	_, err = io.WriteString(tarfileWriter, checksumFileString)
	checkerror(err)



}

func checkerror(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func normalizePath(filename string) string {
	return filepath.Clean(filename)
}

func normalizePaths(filenames []string) []string {
	var absPaths []string

	// Get absolute path for every filename and add to result
	for _, filename := range filenames {
		// Get absolute path for each file
		absPaths = append(absPaths, normalizePath(filename))
	}

	return absPaths
}

func PathIsDirectory(path string) bool {

	// Check if destination is a file or a directory
	fileInfo, err := os.Stat(path)

	if err != nil {
		// Path is no file or directory
		Debug("Path is no file or directory")
		return false
	} else {
		if fileInfo.IsDir() {
			// Path is a directory
			Debug("Path is a directory")
			return true
		} else {
			// Path is a file
			return false
		}
	}
}

func AddRecursively(paths []string) []string {
	var allPaths []string

	walkFcn := func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			allPaths = append(allPaths, path)
		}
		return nil
	}

	// Iterate over all given paths
	for _, path := range paths {
		// Check if path is a directory
		if PathIsDirectory(path) {
			Debug("Directory", path, "found - let's go in.")
			err := filepath.Walk(path, walkFcn)
			if err != nil {
				Error("Could not obtain all files in ", path)
			}
		} else {
			Debug("This is a file. Just add it.")
			allPaths = append(allPaths, path)
		}
	}

	return allPaths
}

func FileExists(file string) bool {
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func calculateChecksum(filename string) string {
	hasher := sha256.New()

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	if _, err := io.Copy(hasher, file); err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func createChecksumString(fileMap map[string]File) string {
	var buffer bytes.Buffer

	// Calculate checksum for every file
	for _, file := range fileMap {
		buffer.WriteString(file.Checksum)
		buffer.WriteString("  ")
		buffer.WriteString(file.PrettyPath)
		buffer.WriteString("\n")
	}

	return buffer.String()
}

func Debug(args ...interface{}) {
	if *debug {
		log.Printf("DEBUG %v", args)
	}
}

func Error(args ...interface{}) {
	log.Printf("ERROR %v", args)
}

func CommonPrefix(sep byte, paths ...string) string {

	// Thanks to http://rosettacode.org/wiki/Find_common_directory_path#Go

	// Handle special cases.
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return filepath.Clean(paths[0])
	}

	// Note, we treat string as []byte, not []rune as is often
	// done in Go. (And sep as byte, not rune). This is because
	// most/all supported OS' treat paths as string of non-zero
	// bytes. A filename may be displayed as a sequence of Unicode
	// runes (typically encoded as UTF-8) but paths are
	// not required to be valid UTF-8 or in any normalized form
	// (e.g. "é" (U+00C9) and "é" (U+0065,U+0301) are different
	// file names.
	c := []byte(filepath.Clean(paths[0]))

	// We add a trailing sep to handle the case where the
	// common prefix directory is included in the path list
	// (e.g. /home/user1, /home/user1/foo, /home/user1/bar).
	// path.Clean will have cleaned off trailing / separators with
	// the exception of the root directory, "/" (in which case we
	// make it "//", but this will get fixed up to "/" bellow).
	c = append(c, sep)

	// Ignore the first path since it's already in c
	for _, v := range paths[1:] {
		// Clean up each path before testing it
		v = filepath.Clean(v) + string(sep)

		// Find the first non-common byte and truncate c
		if len(v) < len(c) {
			c = c[:len(v)]
		}
		for i := 0; i < len(c); i++ {
			if v[i] != c[i] {
				c = c[:i]
				break
			}
		}
	}

	// Remove trailing non-separator characters and the final separator
	for i := len(c) - 1; i >= 0; i-- {
		if c[i] == sep {
			c = c[:i]
			break
		}
	}

	return string(c)
}
