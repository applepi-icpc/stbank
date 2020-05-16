package main

import (
	"crypto/aes"
	"crypto/sha256"
	"os"
	"path/filepath"

	"github.com/applepi-icpc/stbank/aesfs"
	"github.com/billziss-gh/cgofuse/fuse"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Usage: ./stbank [options] <root> <password> <mountpoint>

	args := os.Args
	var (
		root     string
		password string
		err      error
	)

	if len(args) >= 4 && args[len(args)-3][0] != '-' && args[len(args)-2][0] != '-' && args[len(args)-1][0] != '-' {
		rawRoot := args[len(args)-3]
		root, err = filepath.Abs(rawRoot)
		if err != nil {
			log.Fatal("Failed to get path from %s: %s", rawRoot, err.Error())
		}
		password = args[len(args)-2]
		args = append(args[:len(args)-3], args[len(args)-1])
	} else {
		log.Fatalf("Usage: %s [options] <root> <password> <mountpoint>", args[0])
	}

	passwordSHA256 := sha256.Sum256([]byte(password))
	aesKey := passwordSHA256[:]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal("Failed to generate AES key: %s", err.Error())
	}

	fs, err := aesfs.NewAESFS(root, block)
	if err != nil {
		log.Fatal("Failed to init FS: %s", err.Error())
	}

	host := fuse.NewFileSystemHost(fs)
	host.Mount("", args[1:])
}
