package aesrw

import (
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"sync"
)

type Sizer interface {
	Size() (int64, error)
}

type Truncator interface {
	Truncate(size int64) error
}

type File interface {
	io.ReaderAt
	io.WriterAt
	Sizer
	Truncator
	io.Closer
}

type OSFile struct {
	F *os.File
}

func (o *OSFile) Truncate(size int64) error {
	return o.F.Truncate(size)
}

func (o *OSFile) Size() (int64, error) {
	stat, err := o.F.Stat()
	if err != nil {
		return 0, err
	}
	return stat.Size(), nil
}

func (o *OSFile) ReadAt(p []byte, off int64) (n int, err error) {
	return o.F.ReadAt(p, off)
}

func (o *OSFile) WriteAt(p []byte, off int64) (n int, err error) {
	return o.F.WriteAt(p, off)
}

func (o *OSFile) Close() error {
	return o.F.Close()
}

// assert *OSFile implements File
var _ File = (*OSFile)(nil)

type AESFile struct {
	mu         sync.Mutex
	underlying File
	ctr        CTR
	ctrFilled  bool
	block      cipher.Block
}

func NewAESFile(f File, block cipher.Block) *AESFile {
	if block.BlockSize() != BlockSize {
		panic(fmt.Errorf("invalid block size: %d", block.BlockSize()))
	}
	return &AESFile{
		underlying: f,
		ctrFilled:  false,
		block:      block,
	}
}

// assert *AESFile implements File
var _ File = (*AESFile)(nil)

func (f *AESFile) Create() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	ctr, err := RandomCTR()
	if err != nil {
		return err
	}
	return f.createByCTR(ctr)
}

func (f *AESFile) CreateByCTR(ctr CTR) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.createByCTR(ctr)
}

func (f *AESFile) createByCTR(ctr CTR) error {
	err := f.underlying.Truncate(BlockSize)
	if err != nil {
		return err
	}
	_, err = f.underlying.WriteAt(ctr.IV(), 0)
	if err != nil {
		return err
	}
	f.ctr = ctr
	f.ctrFilled = true
	return nil
}

func (f *AESFile) ensureCTR() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.ctrFilled {
		return nil
	}
	_, err := f.underlying.ReadAt(f.ctr[:], 0)
	if err != nil {
		return err
	}
	f.ctrFilled = true
	return nil
}

func (f *AESFile) Truncate(size int64) error {
	currentSize, err := f.Size()
	if err != nil {
		return err
	}

	err = f.underlying.Truncate(size + int64(BlockSize))
	if err != nil {
		return err
	}

	if size <= currentSize {
		return nil
	}

	_, err = f.writeAt(nil, currentSize, true, int(size-currentSize))
	return nil
}

func (f *AESFile) TruncateFillZero(size int64) error {
	return f.underlying.Truncate(size + int64(BlockSize))
}

func (f *AESFile) Size() (int64, error) {
	originalSize, err := f.underlying.Size()
	if err != nil {
		return 0, err
	}
	return originalSize - int64(BlockSize), nil
}

func pad(n int64) (blocks int64, res int64) {
	blocks = n / int64(BlockSize) // floor
	return blocks, blocks * int64(BlockSize)
}

func (f *AESFile) ReadAt(p []byte, off int64) (n int, err error) {
	n = 0
	err = f.ensureCTR()
	if err != nil {
		return
	}

	// read from underlying file
	_, err = f.underlying.ReadAt(p, off+int64(BlockSize))
	if err != nil {
		return
	}

	blocks, begin := pad(off)
	iv := f.ctr.Add(blocks).IV()
	offset := off - begin
	fakeContent := make([]byte, offset)

	ctrStream := cipher.NewCTR(f.block, iv)
	ctrStream.XORKeyStream(fakeContent, fakeContent) // apply offset
	ctrStream.XORKeyStream(p, p)

	return len(p), nil
}

const BufferSize = 65536

func (f *AESFile) writeAt(p []byte, off int64, writeZero bool, zeroSize int) (n int, err error) {
	n = 0
	err = f.ensureCTR()
	if err != nil {
		return
	}

	bufferSize := BufferSize
	var bytesLength int
	if writeZero {
		bytesLength = zeroSize
	} else {
		bytesLength = len(p)
	}
	if bufferSize > bytesLength {
		bufferSize = bytesLength
	}
	buffer := make([]byte, bufferSize)
	writed := 0

	blocks, begin := pad(off)
	iv := f.ctr.Add(blocks).IV()
	offset := off - begin
	fakeContent := make([]byte, offset)
	ctrStream := cipher.NewCTR(f.block, iv)
	ctrStream.XORKeyStream(fakeContent, fakeContent) // apply offset

	for writed < bytesLength {
		remaining := bytesLength - writed
		toWrite := bufferSize
		if toWrite > remaining {
			toWrite = remaining
		}

		if writeZero {
			ctrStream.XORKeyStream(buffer[:toWrite], make([]byte, toWrite))
		} else {
			ctrStream.XORKeyStream(buffer[:toWrite], p[writed:writed+toWrite])
		}

		thisWrited, thisErr := f.underlying.WriteAt(buffer[:toWrite], off+int64(writed)+BlockSize)
		writed += thisWrited
		if thisErr != nil {
			return writed, thisErr
		}
	}

	return writed, nil
}

func (f *AESFile) WriteAt(p []byte, off int64) (n int, err error) {
	size, err := f.Size()
	if err != nil {
		return 0, err
	}
	needSize := off + int64(len(p))
	if needSize > size {
		f.Truncate(needSize)
	}

	return f.writeAt(p, off, false, 0)
}

func (f *AESFile) Close() error {
	return f.underlying.Close()
}
