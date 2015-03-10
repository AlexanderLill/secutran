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

var isVerbose *bool = flag.Bool("v", false, "Verbose output")
var isDebug *bool = flag.Bool("vv", false, "Debugging output")
var flagSource *string = flag.String("source", "", "Source directory or file")
var flagDestination *string = flag.String("destination", "", "Destination directory or file")
var noEncrypt *bool = flag.Bool("noencrypt", false, "Do not encrypt destination")
var overwriteDest *bool = flag.Bool("overwrite", false, "Overwrite destination if it exists")
var useOriginal *bool = flag.Bool("original", false, "Use original paths inside archive instead of possible relative paths")

type SourceFile struct {
	OriginalPath string
	RelativePath string
	Checksum string
}

func (f SourceFile) String() string {
	return "File - RelativePath=" + f.RelativePath + "\n" +
 		   "Checksum=" + f.Checksum + "\n"
}

func main() {

	// Parse the command line options
	flag.Parse()
	Verbose("isVerbose:", *isVerbose)
	Debug("isDebug:", *isDebug)
	Debug("flagSource:", *flagSource)
	Debug("flagDestination:", *flagDestination)
	Verbose("noEncrypt:", *noEncrypt)

	// Check if arguments are provided
	if len(flag.Args()) == 0 {
		log.Fatal("Action not specified! See \"", filepath.Base(os.Args[0]), " -h\"")
	}

	// Action is first argument
	Debug("arguments:", flag.Args())
	action := flag.Args()[0]
	Debug("action:", action)

	// Choose what is to do
	switch action {
	case "encryptto":
		//secutran encryptto <dest> <source, source, source>

		// Get destination
		destination := flag.Args()[1]
		Debug("rawdestination:", destination)
		destFile := getDestinationFile(destination)
		Verbose("destFile:", destFile)

		// Get sources
		sources := flag.Args()[2:]
		Debug("rawsources:", sources)
		sourceFiles := getSourceFiles(sources)
		Debug("sourceFiles:", sourceFiles)

		// Start
		encrypt(sourceFiles, destFile)

	case "encrypt":
		//secutran encrypt <source, source, source> (dest = workingdir)
		//secutran encrypt --destination=<dest> <source, source, source>

		// Get destination
		var destination string
		if *flagDestination == "" {
			dest, err := os.Getwd()
			if err != nil {
				log.Fatal("Could not get current working directory:", err)
			}
			destination = dest
		} else {
			destination = *flagDestination
		}
		Debug("rawdestination:", destination)
		destFile := getDestinationFile(destination)
		Verbose("destFile:", destFile)

		// Get sources
		sources := flag.Args()[1:]
		Debug("rawsources:", sources)
		sourceFiles := getSourceFiles(sources)
		Debug("sourceFiles:", sourceFiles)

		// Start
		encrypt(sourceFiles, destFile)

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

func getDestinationFile(destination string) (destFile string) {

	destFile = filepath.Clean(destination)

	// If path is directory, create filename
	if pathIsDirectory(destFile) {
		if *noEncrypt {
			destFile = destFile + "/destFile.tar.gz" // TODO
		} else {
			destFile = destFile + "/destFile.tar.gz.crypt" // TODO
		}
		Debug("Destination is a directory. Created filename:", destFile)
	}

	// Check if file exists
	if fileExists(destFile) {
		if *overwriteDest {
			Debug("Destination exists. Overwriting ", destFile)
		} else {
			log.Fatal("Destination \"", destFile, "\" does already exist. Aborting. (Try -overwrite to ignore existing destination files.)")
		}
	}

	return
}

func getSourceFiles(sources []string) (sourceFiles []SourceFile) {
	for _, source := range sources {
		sourceFiles = append(sourceFiles, getFilesRecursively(source)...)
	}
	return
}

func getFilesRecursively(source string) (sourceFiles []SourceFile) {
	walkFcn := func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			sourceFiles = append(sourceFiles, SourceFile{OriginalPath: path, RelativePath: path})
		}
		return nil
	}

	source = filepath.Clean(source)

	// Check if source is a directory
	if pathIsDirectory(source) {
		Debug("Going into directory", source)
		err := filepath.Walk(source, walkFcn)
		if err != nil {
			Error("Could not obtain all files in ", source)
		}
	} else {
		Debug("Adding file", source)
		sourceFiles = append(sourceFiles, SourceFile{OriginalPath: source, RelativePath: source})
	}

	return
}

func encrypt(files []SourceFile, destination string) {

	// Check if archive should use smallest possible hierarchy
	if ! *useOriginal {

		// Get all source files to determine common path
		var filesStrings []string
		for _, file := range files {
			filesStrings = append(filesStrings, file.OriginalPath)
		}

		// Get common path
		commonPath := commonPrefix(os.PathSeparator, filesStrings...)
		Debug("Common path:", commonPath)

		// Initialize field "RelativePath" for every file
		for id, file := range files {
			relPath, err := filepath.Rel(commonPath, file.OriginalPath)
			if err != nil {
				Error("Could not get relative path for file", file.OriginalPath, ":", err)
				relPath = file.OriginalPath
			}

			Debug("Relative path: ", relPath)
			files[id].RelativePath = relPath
		}
	}
	
	// Initialize all checksums
	for id, file := range files {
		files[id].Checksum = calculateChecksum(file.OriginalPath)
	}

	// Create destination file
	destFile, err := os.Create(destination)
	defer destFile.Close()
	checkerror(err)

	// Create writers
	var zipWriter io.WriteCloser
	var tarWriter *tar.Writer

	// Check if we encrypt
	if ! *noEncrypt {

		key := []byte("example key 1234")

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		// TODO: Think about if using no initialization vector
		// is secure enough. (But normally same files and same
		// key should result in the same destination file imho.)

		var iv [aes.BlockSize]byte
		stream := cipher.NewCTR(block, iv[:])

		// Writes to cryptWriter are encrypted and written to destFile
		cryptWriter := cipher.StreamWriter{S: stream, W: destFile}

		// Writes to zipWriter are zipped and written to cryptWriter
		zipWriter = gzip.NewWriter(cryptWriter)
		defer zipWriter.Close()

		// Writes to tarWriter are tarred and written to zipWriter
		tarWriter = tar.NewWriter(zipWriter)
		defer tarWriter.Close()

	} else {

		// Writes to zipWriter are zipped and written to destFile
		zipWriter = gzip.NewWriter(destFile)
		defer zipWriter.Close()

		// Writes to tarWriter are tarred and written to zipWriter
		tarWriter = tar.NewWriter(zipWriter)
		defer tarWriter.Close()
	}

	// Create buffer for file with checksums
	var checksumFileBuf bytes.Buffer

	// Iterate over all source files
	for _, file := range files {

		// Add file to checksumfile
		checksumFileBuf.WriteString(file.Checksum)
		checksumFileBuf.WriteString("  ")
		checksumFileBuf.WriteString(file.RelativePath)
		checksumFileBuf.WriteString("\n")

		// Get file info
		fileInfo, err := os.Stat(file.OriginalPath)
		if err != nil {
			log.Fatal("Could not retrieve file info for file ", file.OriginalPath)
		}

		if fileInfo.IsDir() {
			continue
		}

		Verbose("Adding " + file.RelativePath + " ...")
		fileHandle, err := os.Open(file.OriginalPath)
		defer fileHandle.Close()
		checkerror(err)

		// prepare the tar header
		header := new(tar.Header)
		header.Name = file.RelativePath
		header.Size = fileInfo.Size()
		header.Mode = int64(fileInfo.Mode())
		header.ModTime = fileInfo.ModTime()

		err = tarWriter.WriteHeader(header)
		checkerror(err)

		_, err = io.Copy(tarWriter, fileHandle)
		checkerror(err)
	}

	Verbose("Adding checksums.sha256 ...")
	checksumFileString := checksumFileBuf.String()

	// Add file with checksums to tar
	// TODO: Calculation of checksums could be parallelized to tar-creation
	checksumHeader := new(tar.Header)
	checksumHeader.Name = "checksums.sha256"
	checksumHeader.Size = int64(len(checksumFileString))
	checksumHeader.Mode = int64(0644)
	checksumHeader.ModTime = time.Now()

	err = tarWriter.WriteHeader(checksumHeader)
	checkerror(err)

	_, err = io.WriteString(tarWriter, checksumFileString)
	checkerror(err)

	Verbose("All done!")
}

func checkerror(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func pathIsDirectory(path string) bool {

	fileInfo, err := os.Stat(path)

	if err != nil {
		// Path is no file or directory
		Debug("Path is no file or directory:", path)
		return false
	} else {
		if fileInfo.IsDir() {
			// Path is a directory
			Debug("Path is a directory:", path)
			return true
		} else {
			// Path is a file
			Debug("Path is a file:", path)
			return false
		}
	}
}

func fileExists(file string) bool {
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		Debug("File does not exist:", file)
		return false
	}
	Debug("File exists:", file)
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

func Verbose(args ...interface{}) {
	if *isVerbose || *isDebug {
		log.Print(args)
	}
}

func Debug(args ...interface{}) {
	if *isDebug {
		log.Printf("debug %v", args)
	}
}

func Error(args ...interface{}) {
	log.Printf("ERROR %v", args)
}

func commonPrefix(sep byte, paths ...string) string {

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