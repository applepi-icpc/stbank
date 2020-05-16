package aesrw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"
)

type FakeFile struct {
	b []byte
}

func NewFakeFile() *FakeFile {
	return &FakeFile{
		b: make([]byte, 0),
	}
}

func (f *FakeFile) ensureLength(size int64) {
	if int64(len(f.b)) >= size {
		return
	} else {
		originalSize := len(f.b)
		newB := make([]byte, size)
		copy(newB[:originalSize], f.b)
		f.b = newB
	}
}

func (f *FakeFile) Size() (int64, error) {
	return int64(len(f.b)), nil
}

func (f *FakeFile) Truncate(size int64) error {
	if int64(len(f.b)) >= size {
		f.b = f.b[:size]
	} else {
		f.ensureLength(size)
	}
	return nil
}

func (f *FakeFile) ReadAt(p []byte, off int64) (n int, err error) {
	maxRead := int64(len(f.b)) - off
	actualRead := int64(len(p))
	if actualRead > maxRead {
		actualRead = maxRead
	}
	copy(p, f.b[off:off+actualRead])
	n = int(actualRead)
	if n < len(p) {
		err = io.ErrUnexpectedEOF
	} else {
		err = nil
	}
	return
}

func (f *FakeFile) WriteAt(p []byte, off int64) (n int, err error) {
	needLength := off + int64(len(p))
	f.ensureLength(needLength)

	n = len(p)
	offInt := int(off)
	copy(f.b[offInt:offInt+n], p)
	err = nil
	return
}

func (f *FakeFile) Close() error {
	return nil
}

func (f *FakeFile) Bytes() []byte {
	return f.b
}

type WR struct {
	B []byte
	O int64
}

func TestAESRW(t *testing.T) {
	f1 := NewFakeFile()
	f2 := NewFakeFile()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read key: %s", err.Error())
	}
	bloc, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to make block: %s", err.Error())
	}
	af := NewAESFile(f1, bloc)

	ctr, err := RandomCTR()
	if err != nil {
		t.Fatalf("Failed to make ctr: %s", err.Error())
	}
	af.CreateByCTR(ctr)

	// reopen to check whether CTR is OK to read from file
	af = NewAESFile(f1, bloc)

	// write something
	requests := []*WR{
		{
			B: []byte("blahblahblahb"),
			O: 0,
		},
		{
			B: []byte("niconiconi"),
			O: 3,
		},
		{
			B: []byte("666666"),
			O: 31,
		},
		{
			B: []byte("233333"),
			O: 18,
		},
	}
	for k, req := range requests {
		_, err := f2.WriteAt(req.B, req.O)
		if err != nil {
			t.Fatalf("Raw: Failed to finish request %d: %s", k, err.Error())
		}
		_, err = af.WriteAt(req.B, req.O)
		if err != nil {
			t.Fatalf("Encrypted: Failed to finish request %d: %s", k, err.Error())
		}
	}

	// check encrypt from stretch
	ctrStream := cipher.NewCTR(bloc, ctr.IV())
	raw := f2.Bytes()
	b := make([]byte, len(raw))
	ctrStream.XORKeyStream(b, raw)
	get := f1.Bytes()[BlockSize:]
	if !bytes.Equal(get, b) {
		t.Errorf("Bytes mismatch: %v <=> %v", get, b)
	}

	// check decryption
	ctrStream = cipher.NewCTR(bloc, ctr.IV())
	ctrStream.XORKeyStream(b, get)
	if !bytes.Equal(raw, b) {
		t.Errorf("Bytes mismatch: %v <=> %v", raw, b)
	}

	// check open again and read
	af2 := NewAESFile(f1, bloc)
	_, err = af2.ReadAt(b, 0)
	if err != nil {
		t.Fatalf("Failed to read from reopened AES file: %s", err.Error())
	}
	if !bytes.Equal(raw, b) {
		t.Errorf("Bytes mismatch: %v <=> %v", raw, b)
	}
}
