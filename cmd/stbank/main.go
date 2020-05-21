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
	// Usage: ./stbank <root> <password> [options] <mountpoint>

	args := os.Args
	var (
		root     string
		password string
		err      error
	)

	log.SetLevel(log.WarnLevel)

	if len(args) >= 4 && args[1][0] != '-' && args[2][0] != '-' && args[len(args)-1][0] != '-' {
		rawRoot := args[1]
		root, err = filepath.Abs(rawRoot)
		if err != nil {
			log.Fatalf("Failed to get path from %s: %s", rawRoot, err.Error())
		}
		password = args[2]
		args = append(args[3:])
	} else {
		log.Fatalf("Usage: %s <root> <password> [options] <mountpoint>", args[0])
	}

	passwordSHA256 := sha256.Sum256([]byte(password))
	aesKey := passwordSHA256[:]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatalf("Failed to generate AES key: %s", err.Error())
	}

	fs, err := aesfs.NewAESFS(root, block)
	if err != nil {
		log.Fatalf("Failed to init FS: %s", err.Error())
	}

	host := fuse.NewFileSystemHost(fs)
	host.Mount("", args)
}
