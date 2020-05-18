package aesfs

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/applepi-icpc/stbank/aesrw"
	"github.com/billziss-gh/cgofuse/fuse"
	"github.com/ricochet2200/go-disk-usage/du"
	log "github.com/sirupsen/logrus"
)

func split(path string) []string {
	return strings.Split(path, "/")
}

type NodeID = int64

type Node struct {
	Stat     fuse.Stat_t       `json:"s"`
	XAttr    map[string][]byte `json:"x"`
	Children map[string]NodeID `json:"c"`
}

func NewNode(dev uint64, ino uint64, mode uint32, uid uint32, gid uint32) *Node {
	now := fuse.Now()
	res := &Node{
		Stat: fuse.Stat_t{
			Dev:      dev,
			Ino:      ino,
			Mode:     mode,
			Nlink:    1,
			Uid:      uid,
			Gid:      gid,
			Atim:     now,
			Mtim:     now,
			Ctim:     now,
			Birthtim: now,
			Flags:    0,
		},
		XAttr:    make(map[string][]byte),
		Children: nil,
	}

	if mode&fuse.S_IFMT == fuse.S_IFDIR {
		res.Children = make(map[string]NodeID)
	}

	return res
}

func (node *Node) IsDir() bool {
	return node.Stat.Mode&fuse.S_IFMT == fuse.S_IFDIR
}

func (node *Node) IsLink() bool {
	return node.Stat.Mode&fuse.S_IFMT == fuse.S_IFLNK
}

const (
	TotalFiles    = 1000000000
	FileBlockSize = 1024
	NameMax       = 255
)

type AESFSMeta struct {
	CurrentIno  NodeID `json:"c"`
	TotalBlocks uint64 `json:"tb"`
	TotalFiles  uint64 `json:"tf"`
}

type NodeCache struct {
	ID        NodeID
	Node      *Node
	Dirty     bool
	LastTouch time.Time
	Occupied  bool
}

const CacheSize = 32

type AESFS struct {
	fuse.FileSystemBase
	mu sync.Mutex

	blockEncryption cipher.Block
	meta            *AESFSMeta
	rootDir         string // root dir on actual file system

	openmap     map[NodeID]*Node
	opencount   map[NodeID]int
	openedFiles map[NodeID]*aesrw.AESFile

	metaShouldDump bool
	metaDumpTime   time.Time

	nodeCacheMu sync.Mutex
	nodeCache   []*NodeCache
}

func (fs *AESFS) actualPath(filename string) string {
	return filepath.Join(fs.rootDir, filename)
}

func (fs *AESFS) inoPath(ino NodeID, suffix string) string {
	d := ino
	d1 := d & 0xFF
	d >>= 8
	d2 := d & 0xFF
	d >>= 8

	var fileName string
	if suffix == "" {
		fileName = fmt.Sprintf("%02x/%02x/%012x", d1, d2, d)
	} else {
		fileName = fmt.Sprintf("%02x/%02x/%012x.%s", d1, d2, d, suffix)
	}

	return fs.actualPath(fileName)
}

func ensureActualDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, os.FileMode(0755))
}

type CreateFlag int

const (
	CREATE_AUTO CreateFlag = iota
	CREATE_MUST
	CREATE_NO
)

func (fs *AESFS) openActualFile(path string, createFlag CreateFlag, withdrawFailOK bool) (*aesrw.AESFile, error) {
	ensureActualDir(path)

	var create bool
	if createFlag == CREATE_AUTO {
		create = false
		if _, err := os.Stat(path); os.IsNotExist(err) {
			create = true
		}
	} else if createFlag == CREATE_MUST {
		create = true
	} else if createFlag == CREATE_NO {
		create = false
	} else {
		panic(fmt.Errorf("invalid create flag: %d", createFlag))
	}

	if create {
		// create file
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return nil, err
		}
		aesFile := aesrw.NewAESFile(&aesrw.OSFile{F: f}, fs.blockEncryption)
		err = aesFile.Create()
		if err != nil {
			f.Close()
			removeErr := os.Remove(path)
			if removeErr != nil {
				log.WithFields(log.Fields{
					"error": err,
					"path":  path,
				}).Error("Failed to withdraw file creation")

				// failed to withdraw, there may be a corrupted file
				if !withdrawFailOK {
					panic(removeErr)
				}
			}
			return nil, err
		}
		return aesFile, nil
	} else {
		// open existing file
		f, err := os.OpenFile(path, os.O_RDWR, 0666)
		if err != nil {
			return nil, err
		}
		aesFile := aesrw.NewAESFile(&aesrw.OSFile{F: f}, fs.blockEncryption)
		return aesFile, nil
	}
}

func randomSuffix() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%02x", b)
}

func (fs *AESFS) dumpFile(path string, content []byte) error {
	suffix := randomSuffix()
	dumpPath := fmt.Sprintf("%s.%s.tmp", path, suffix)

	af, err := fs.openActualFile(dumpPath, CREATE_MUST, true)
	if err != nil {
		return err
	}

	_, err = af.WriteAt(content, 0)
	if err != nil {
		af.Close()
		os.Remove(dumpPath) // withdraw fail is OK
		return err
	}

	af.Close()
	return os.Rename(dumpPath, path)
}

func (fs *AESFS) readFile(path string) ([]byte, error) {
	af, err := fs.openActualFile(path, CREATE_NO, false)
	if err != nil {
		return nil, err
	}
	defer af.Close()

	size, err := af.Size()
	if err != nil {
		return nil, err
	}
	b := make([]byte, size)

	_, err = af.ReadAt(b, 0)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (fs *AESFS) readMeta() error {
	b, err := fs.readFile(fs.actualPath("meta"))
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &fs.meta)
	if err != nil {
		log.Error("Failed to unmarshal meta, the meta file may be corrupted")
		panic(err)
	}

	return nil
}

func (fs *AESFS) dumpMeta() error {
	b, err := json.Marshal(fs.meta)
	if err != nil {
		// impossible
		panic(err)
	}

	err = fs.dumpFile(fs.actualPath("meta"), b)
	return err
}

func (fs *AESFS) scheduleMetaDump() {
	// no lock

	if !fs.metaShouldDump {
		fs.metaShouldDump = true
		fs.metaDumpTime = time.Now().Add(time.Second * 30)
	}
}

func (fs *AESFS) _checkMetaDump() {
	if fs.metaShouldDump {
		err := fs.dumpMeta()
		if err != nil {
			log.WithError(err).Error("Failed to dump meta")
		} else {
			log.Info("Meta dumped")
			fs.metaShouldDump = false
		}
	}
}

func (fs *AESFS) checkMetaDump() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs._checkMetaDump()
}

func (fs *AESFS) checkMetaDumpLoop() {
	for {
		time.Sleep(time.Second)
		now := time.Now()
		fs.mu.Lock()
		if fs.metaDumpTime.Before(now) {
			fs._checkMetaDump()
		}
		fs.mu.Unlock()
	}
}

func (fs *AESFS) readNode(ino NodeID) (*Node, error) {
	// low level node read API, use getNode instead

	b, err := fs.readFile(fs.inoPath(ino, "i"))
	if err != nil {
		return nil, err
	}

	var res *Node
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (fs *AESFS) dumpNode(ino NodeID, node *Node) error {
	b, err := json.Marshal(node)
	if err != nil {
		// impossible
		panic(err)
	}

	err = fs.dumpFile(fs.inoPath(ino, "i"), b)
	return err
}

const (
	ROOT_INO    = 0
	INVALID_INO = -1
)

func NewAESFS(rootDir string, blockEncryption cipher.Block) (*AESFS, error) {
	res := &AESFS{
		blockEncryption: blockEncryption,
		meta:            nil,
		rootDir:         rootDir,
		openmap:         make(map[int64]*Node),
		opencount:       make(map[int64]int),
		openedFiles:     make(map[int64]*aesrw.AESFile),
	}
	if _, err := os.Stat(res.actualPath("meta")); os.IsNotExist(err) {
		// make a totally new file system
		res.meta = &AESFSMeta{
			CurrentIno:  ROOT_INO + 1,
			TotalBlocks: 0,
			TotalFiles:  0,
		}
		err = res.dumpMeta()
		if err != nil {
			return nil, err
		}

		// make root inode
		rootNode := NewNode(0, ROOT_INO, fuse.S_IFDIR|00777, 0, 0)
		err = res.dumpNode(ROOT_INO, rootNode)
		if err != nil {
			return nil, err
		}
	} else {
		err = res.readMeta()
		if err != nil {
			return nil, err
		}
	}

	go res.checkMetaDumpLoop()

	res.nodeCache = make([]*NodeCache, CacheSize)
	for k := range res.nodeCache {
		res.nodeCache[k] = &NodeCache{}
	}

	go res.scanCacheLoop()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		_, ok := <-sig
		if ok {
			res.exitSignalHandler()
		}
	}()

	return res, nil
}

func (fs *AESFS) exitSignalHandler() {
	fs.checkMetaDump()

	fs.nodeCacheMu.Lock()
	defer fs.nodeCacheMu.Unlock()

	for _, entry := range fs.nodeCache {
		if entry.Occupied && entry.Dirty {
			fs.writeBackNode(entry)
		}
	}
}

func (fs *AESFS) findInCache(ino NodeID) *Node {
	fs.nodeCacheMu.Lock()
	defer fs.nodeCacheMu.Unlock()

	for _, entry := range fs.nodeCache {
		if entry.Occupied && entry.ID == ino {
			entry.LastTouch = time.Now()
			return entry.Node
		}
	}

	return nil
}

func (fs *AESFS) writeBackNode(entry *NodeCache) {
	// no lock

	err := fs.dumpNode(entry.ID, entry.Node)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"id":    entry.ID,
		}).Error("Failed to dump node")
	} else {
		log.WithField("id", entry.ID).Info("Node wrote back")
		entry.Dirty = false
	}
}

func (fs *AESFS) findEmptyEntry() (index int) {
	// no lock

	index = -1
	earliestLastTouch := time.Now()

	for i, entry := range fs.nodeCache {
		if !entry.Occupied {
			return i
		}
		if entry.LastTouch.Before(earliestLastTouch) {
			earliestLastTouch = entry.LastTouch
			index = i
		}
	}

	if index == -1 {
		panic("not evicted anything")
	}
	entry := fs.nodeCache[index]
	if entry.Dirty {
		fs.writeBackNode(entry)
	}

	return
}

func (fs *AESFS) writeToCache(ino NodeID, node *Node, dirty bool) {
	fs.nodeCacheMu.Lock()
	defer fs.nodeCacheMu.Unlock()

	for _, entry := range fs.nodeCache {
		if entry.Occupied && entry.ID == ino {
			entry.Node = node
			entry.Dirty = dirty
			entry.LastTouch = time.Now()
			return
		}
	}

	index := fs.findEmptyEntry()

	entry := fs.nodeCache[index]
	entry.ID = ino
	entry.Node = node
	entry.Dirty = dirty
	entry.LastTouch = time.Now()
	entry.Occupied = true
}

func (fs *AESFS) scanCacheLoop() {
	for {
		time.Sleep(time.Second)

		func() {
			bar := time.Now().Add(-time.Second * 5)

			fs.nodeCacheMu.Lock()
			defer fs.nodeCacheMu.Unlock()

			for _, entry := range fs.nodeCache {
				if entry.Occupied && entry.Dirty && entry.LastTouch.Before(bar) {
					fs.writeBackNode(entry)
				}
			}
		}()
	}
}

func (fs *AESFS) getNode(ino NodeID) (*Node, error) {
	fs.mu.Lock()
	node, exist := fs.openmap[ino]
	if exist {
		fs.mu.Unlock()
		return node, nil
	}
	fs.mu.Unlock()

	cachedNode := fs.findInCache(ino)
	if cachedNode != nil {
		return cachedNode, nil
	}

	node, err := fs.readNode(ino)
	if err != nil {
		return nil, err
	}

	fs.writeToCache(ino, node, false)
	return node, nil
}

func (fs *AESFS) getNodeByPath(path string, fh uint64) (node NodeID, nodeObject *Node, errno int, err error) {
	if fh == ^uint64(0) {
		_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
		if node == INVALID_INO {
			errno = -fuse.ENOENT
		}
		return
	} else {
		node = NodeID(fh)
		nodeObject, err = fs.getNode(NodeID(fh))
		errno = 0
		return
	}
}

func (fs *AESFS) lookupNode(path string, ancestor NodeID) (parent NodeID, name string, node NodeID, nodeObject *Node, errno int, err error) {
	parent, name, node = ROOT_INO, "", ROOT_INO
	nodeObject = nil
	errno, err = 0, nil

	nodeObject, err = fs.getNode(ROOT_INO)
	if err != nil {
		return
	}

	for _, c := range split(path) {
		if c == "" {
			continue
		}
		if len(c) > NameMax {
			errno = -fuse.ENAMETOOLONG
			return
		}
		if node == INVALID_INO {
			errno = -fuse.ENOENT
			return
		}
		if !nodeObject.IsDir() {
			errno = -fuse.ENOTDIR
			return
		}

		var (
			exist   bool
			newNode NodeID
		)
		newNode, exist = nodeObject.Children[c]
		if !exist {
			newNode = INVALID_INO
		}

		parent, name = node, c
		node = newNode
		if ancestor != INVALID_INO && node == ancestor {
			name = ""
			return
		}

		if newNode == INVALID_INO {
			nodeObject = nil
		} else {
			nodeObject, err = fs.getNode(node)
			if err != nil {
				return
			}
		}
	}

	return
}

func (fs *AESFS) makeNode(path string, mode uint32, dev uint64, data []byte) (errno int, err error) {
	parent, name, node, _, errno, err := fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		return
	}
	if node != INVALID_INO {
		errno = -fuse.EEXIST
		return
	}

	var parentObject *Node
	parentObject, err = fs.getNode(parent)
	if err != nil {
		return
	}

	var newIno NodeID
	func() {
		fs.mu.Lock()
		defer fs.mu.Unlock()

		newIno = fs.meta.CurrentIno
		fs.meta.CurrentIno += 1
		fs.meta.TotalFiles += 1
		if data != nil {
			fs.meta.TotalBlocks += uint64(len(data) / FileBlockSize)
		}

		fs.scheduleMetaDump()
	}()

	uid, gid, _ := fuse.Getcontext()
	newNode := NewNode(dev, uint64(newIno), mode, uid, gid)

	if data != nil {
		err = fs.dumpFile(fs.inoPath(newIno, "c"), data)
		if err != nil {
			return
		}
		newNode.Stat.Size = int64(len(data))
	}

	fs.writeToCache(newIno, newNode, true)

	parentObject.Children[name] = newIno
	parentObject.Stat.Ctim = newNode.Stat.Ctim
	parentObject.Stat.Mtim = newNode.Stat.Ctim
	fs.writeToCache(parent, parentObject, true)

	return
}

func (fs *AESFS) removeNode(path string, dir bool) (errno int, err error) {
	parent, name, node, nodeObject, errno, err := fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}
	if !dir && nodeObject.IsDir() {
		errno = -fuse.EISDIR
		return
	}
	if dir && !nodeObject.IsDir() {
		errno = -fuse.ENOTDIR
		return
	}
	if nodeObject.IsDir() && len(nodeObject.Children) > 0 {
		errno = -fuse.ENOTEMPTY
		return
	}

	now := fuse.Now()
	removed := false

	nodeObject.Stat.Nlink -= 1
	if nodeObject.Stat.Nlink == 0 {
		// TODO: race condition
		os.Remove(fs.inoPath(node, "c"))
		os.Remove(fs.inoPath(node, "i"))
		removed = true
	} else {
		nodeObject.Stat.Ctim = now
		fs.writeToCache(node, nodeObject, true)
	}

	var parentObject *Node
	parentObject, err = fs.getNode(parent)
	if err != nil {
		return
	}

	delete(parentObject.Children, name)
	parentObject.Stat.Ctim = now
	parentObject.Stat.Mtim = now
	fs.writeToCache(parent, parentObject, true)

	if removed {
		func() {
			fs.mu.Lock()
			defer fs.mu.Unlock()

			fs.meta.TotalFiles -= 1
			fs.meta.TotalBlocks -= uint64(nodeObject.Stat.Size / FileBlockSize)
			fs.scheduleMetaDump()
		}()
	}

	return
}

func (fs *AESFS) openNode(path string, dir bool) (errno int, err error, fh uint64) {
	var (
		node       NodeID
		nodeObject *Node
	)
	fh = ^uint64(0)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}
	if !dir && nodeObject.IsDir() {
		errno = -fuse.EISDIR
		return
	}
	if dir && !nodeObject.IsDir() {
		errno = -fuse.ENOTDIR
		return
	}

	func() {
		fs.mu.Lock()
		defer fs.mu.Unlock()

		cnt, exist := fs.opencount[node]
		if !exist {
			if !dir {
				var af *aesrw.AESFile
				af, err = fs.openActualFile(fs.inoPath(node, "c"), CREATE_AUTO, false)
				if err != nil {
					return
				}

				fs.openedFiles[node] = af
			}

			fs.opencount[node] = 1
			fs.openmap[node] = nodeObject
		} else {
			fs.opencount[node] = cnt + 1
		}
	}()

	if err != nil {
		errno = -fuse.EIO
	}

	fh = uint64(node)
	return
}

func (fs *AESFS) closeNode(fh uint64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	nodeID := NodeID(fh)

	cnt, exist := fs.opencount[nodeID]
	if !exist {
		return
	}
	if cnt <= 1 {
		// remove node
		delete(fs.opencount, nodeID)
		delete(fs.openmap, nodeID)

		_, exist := fs.openedFiles[nodeID]
		if exist {
			err := fs.openedFiles[nodeID].Close()
			if err != nil {
				log.WithFields(log.Fields{
					"error":   err,
					"node_id": nodeID,
				}).Error("Failed to close content file")
			}
		}

		delete(fs.openedFiles, nodeID)
	} else {
		fs.opencount[nodeID] = cnt - 1
	}
}

func (fs *AESFS) Statfs(path string, stat *fuse.Statfs_t) (errno int) {
	var err error
	defer Trace(path)(&err, &errno)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	usage := du.NewDiskUsage(fs.rootDir)
	freeBytes := usage.Free()
	freeBlocks := freeBytes / FileBlockSize

	stat.Bsize = FileBlockSize
	stat.Frsize = FileBlockSize
	stat.Blocks = freeBlocks + fs.meta.TotalBlocks
	stat.Bfree = freeBlocks
	stat.Bavail = freeBlocks
	stat.Files = fs.meta.TotalFiles
	stat.Ffree = TotalFiles - uint64(fs.meta.TotalFiles)
	stat.Favail = TotalFiles - uint64(fs.meta.TotalFiles)
	stat.Namemax = NameMax

	return
}

func (fs *AESFS) Mknod(path string, mode uint32, dev uint64) (errno int) {
	var err error
	defer Trace(path, mode, dev)(&err, &errno)

	errno, err = fs.makeNode(path, mode, dev, nil)
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

func (fs *AESFS) Mkdir(path string, mode uint32) (errno int) {
	var err error
	defer Trace(path, mode)(&err, &errno)

	errno, err = fs.makeNode(path, fuse.S_IFDIR|(mode&07777), 0, nil)
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

func (fs *AESFS) Unlink(path string) (errno int) {
	var err error
	defer Trace(path)(&err, &errno)

	errno, err = fs.removeNode(path, false)
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

func (fs *AESFS) Rmdir(path string) (errno int) {
	var err error
	defer Trace(path)(&err, &errno)

	errno, err = fs.removeNode(path, true)
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

func (fs *AESFS) Link(oldpath string, newpath string) (errno int) {
	var err error
	defer Trace(oldpath, newpath)(&err, &errno)

	var (
		oldNode, newParentNode, newNode    NodeID
		newName                            string
		oldNodeObject, newParentNodeObject *Node
	)

	_, _, oldNode, oldNodeObject, errno, err = fs.lookupNode(oldpath, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if oldNode == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	newParentNode, newName, newNode, _, errno, err = fs.lookupNode(newpath, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if newNode != INVALID_INO {
		errno = -fuse.EEXIST
		return
	}

	newParentNodeObject, err = fs.getNode(newParentNode)
	if err != nil {
		errno = -fuse.EIO
		return
	}

	// actual modification
	oldNodeObject.Stat.Nlink += 1
	newParentNodeObject.Children[newName] = oldNode
	now := fuse.Now()
	oldNodeObject.Stat.Ctim = now
	newParentNodeObject.Stat.Ctim = now
	newParentNodeObject.Stat.Mtim = now

	// dump
	fs.writeToCache(oldNode, oldNodeObject, true)
	fs.writeToCache(newParentNode, newParentNodeObject, true)

	return
}

func (fs *AESFS) Symlink(target string, newpath string) (errno int) {
	var err error
	defer Trace(target, newpath)(&err, &errno)

	errno, err = fs.makeNode(newpath, fuse.S_IFLNK|00777, 0, []byte(target))
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

func (fs *AESFS) Readlink(path string) (errno int, target string) {
	var err error
	defer Trace(path)(&err, &errno, &target)

	target = ""
	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}
	if !nodeObject.IsLink() {
		errno = -fuse.EINVAL
		return
	}

	var data []byte
	data, err = fs.readFile(fs.inoPath(node, "c"))
	if err != nil {
		errno = -fuse.EIO
		return
	}

	target = string(data)
	return
}

func (fs *AESFS) Rename(oldpath string, newpath string) (errno int) {
	var err error
	defer Trace(oldpath, newpath)(&err, &errno)

	var (
		oldParentNode, oldNode, newParentNode, newNode          NodeID
		oldName, newName                                        string
		oldParentNodeObject, newParentNodeObject, newNodeObject *Node
	)

	oldParentNode, oldName, oldNode, _, errno, err = fs.lookupNode(oldpath, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if oldNode == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	newParentNode, newName, newNode, _, errno, err = fs.lookupNode(newpath, oldNode)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if newName == "" {
		// guard against directory loop creation
		errno = -fuse.EINVAL
		return
	}
	if oldParentNode == newParentNode && oldName == newName {
		return 0
	}
	if newNode != INVALID_INO {
		errno, err = fs.removeNode(newpath, newNodeObject.IsDir())
		if errno < 0 || err != nil {
			if err != nil {
				errno = -fuse.EIO
			}
			return
		}
	}

	oldParentNodeObject, err = fs.getNode(oldParentNode)
	if err != nil {
		errno = -fuse.EIO
		return
	}
	if newParentNode != oldParentNode {
		newParentNodeObject, err = fs.getNode(newParentNode)
		if err != nil {
			errno = -fuse.EIO
			return
		}
	} else {
		newParentNodeObject = oldParentNodeObject
	}

	// actual modification
	delete(oldParentNodeObject.Children, oldName)
	newParentNodeObject.Children[newName] = oldNode

	// dump
	fs.writeToCache(oldParentNode, oldParentNodeObject, true)
	if oldParentNode != newParentNode {
		fs.writeToCache(newParentNode, newParentNodeObject, true)
	}

	return
}

func (fs *AESFS) Chmod(path string, mode uint32) (errno int) {
	var err error
	defer Trace(path, mode)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	nodeObject.Stat.Mode = (nodeObject.Stat.Mode & fuse.S_IFMT) | (mode & 07777)
	nodeObject.Stat.Ctim = fuse.Now()

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Chown(path string, uid uint32, gid uint32) (errno int) {
	var err error
	defer Trace(path, uid, gid)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	if uid != ^uint32(0) {
		nodeObject.Stat.Uid = uid
	}
	if gid != ^uint32(0) {
		nodeObject.Stat.Gid = gid
	}
	nodeObject.Stat.Ctim = fuse.Now()

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Utimens(path string, timestamp []fuse.Timespec) (errno int) {
	var err error
	defer Trace(path, timestamp)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	nodeObject.Stat.Ctim = fuse.Now()
	if timestamp == nil {
		t := nodeObject.Stat.Ctim
		timestamp = []fuse.Timespec{t, t}
	}
	nodeObject.Stat.Atim = timestamp[0]
	nodeObject.Stat.Mtim = timestamp[1]

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Open(path string, flags int) (errno int, fh uint64) {
	var err error
	defer Trace(path, flags)(&err, &errno, &fh)

	errno, err, fh = fs.openNode(path, false)
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

func statDecorateForGet(stat fuse.Stat_t) fuse.Stat_t {
	// make everyone has permission
	stat.Mode = (stat.Mode & fuse.S_IFMT) | 0777
	stat.Uid = 0
	stat.Gid = 0
	return stat
}

func (fs *AESFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) (errno int) {
	var err error
	defer Trace(path, fh)(&err, &errno)

	var nodeObject *Node
	_, nodeObject, errno, err = fs.getNodeByPath(path, fh)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}

	resStat := statDecorateForGet(nodeObject.Stat)
	*stat = resStat
	return
}

func (fs *AESFS) Truncate(path string, size int64, fh uint64) (errno int) {
	var err error
	defer Trace(path, size, fh)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	node, nodeObject, errno, err = fs.getNodeByPath(path, fh)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}

	var af aesrw.File
	af, err = fs.openActualFile(fs.inoPath(node, "c"), CREATE_NO, false)
	if err != nil {
		errno = -fuse.EIO
		return
	}
	defer af.Close()

	err = af.Truncate(size)
	if err != nil {
		errno = -fuse.EIO
		return
	}

	oldSize := nodeObject.Stat.Size
	nodeObject.Stat.Size = size
	now := fuse.Now()
	nodeObject.Stat.Ctim = now
	nodeObject.Stat.Mtim = now

	// dump
	fs.writeToCache(node, nodeObject, true)

	// modify meta
	oldBlocks := oldSize / FileBlockSize
	newBlocks := size / FileBlockSize
	if oldBlocks != newBlocks {
		func() {
			fs.mu.Lock()
			defer fs.mu.Unlock()

			fs.meta.TotalBlocks += uint64(newBlocks)
			fs.meta.TotalBlocks -= uint64(oldBlocks)

			fs.scheduleMetaDump()
		}()
	}

	return
}

func (fs *AESFS) Read(path string, buffer []byte, offset int64, fh uint64) (n int) {
	var err error
	defer Trace(path, fmt.Sprintf("buffer[%d]", len(buffer)), offset, fh)(&err, &n)

	var (
		node       NodeID
		nodeObject *Node
	)
	node, nodeObject, n, err = fs.getNodeByPath(path, fh)
	if n < 0 || err != nil {
		if err != nil {
			n = -fuse.EIO
		}
		return
	}

	endOffset := offset + int64(len(buffer))
	if endOffset > nodeObject.Stat.Size {
		endOffset = nodeObject.Stat.Size
	}
	readLength := endOffset - offset
	if readLength <= 0 {
		n = 0
		return
	}

	var (
		af    aesrw.File
		exist bool
	)
	fs.mu.Lock()
	af, exist = fs.openedFiles[node]
	fs.mu.Unlock()

	if !exist {
		af, err = fs.openActualFile(fs.inoPath(node, "c"), CREATE_AUTO, false)
		if err != nil {
			n = -fuse.EIO
			return
		}
		defer af.Close()
	}

	n, err = af.ReadAt(buffer[:readLength], offset)
	if err != nil {
		n = -fuse.EIO
		return
	}

	// now := fuse.Now()
	// nodeObject.Stat.Atim = now

	// dump
	// fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Write(path string, buffer []byte, offset int64, fh uint64) (n int) {
	var err error
	defer Trace(path, fmt.Sprintf("buffer[%d]", len(buffer)), offset, fh)(&err, &n)

	var (
		node       NodeID
		nodeObject *Node
	)
	node, nodeObject, n, err = fs.getNodeByPath(path, fh)
	if n < 0 || err != nil {
		if err != nil {
			n = -fuse.EIO
		}
		return
	}

	var (
		af    *aesrw.AESFile
		exist bool
	)
	fs.mu.Lock()
	af, exist = fs.openedFiles[node]
	fs.mu.Unlock()

	if !exist {
		af, err = fs.openActualFile(fs.inoPath(node, "c"), CREATE_AUTO, false)
		if err != nil {
			n = -fuse.EIO
			return
		}
		defer af.Close()
	}

	endOffset := offset + int64(len(buffer))
	if endOffset > nodeObject.Stat.Size {
		oldSize := nodeObject.Stat.Size
		nodeObject.Stat.Size = endOffset

		if oldSize < offset {
			err = af.Truncate(endOffset)
		} else {
			err = af.TruncateFillZero(endOffset)
		}
		if err != nil {
			n = -fuse.EIO
			return
		}

		// modify meta
		oldBlocks := oldSize / FileBlockSize
		newBlocks := endOffset / FileBlockSize
		if oldBlocks != newBlocks {
			func() {
				fs.mu.Lock()
				defer fs.mu.Unlock()

				fs.meta.TotalBlocks += uint64(newBlocks)
				fs.meta.TotalBlocks -= uint64(oldBlocks)

				fs.scheduleMetaDump()
			}()
		}
	}

	n, err = af.WriteAt(buffer, offset)
	if err != nil {
		n = -fuse.EIO
		return
	}

	now := fuse.Now()
	nodeObject.Stat.Ctim = now
	nodeObject.Stat.Mtim = now

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Release(path string, fh uint64) (errno int) {
	var err error
	defer Trace(path, fh)(&err, &errno)

	fs.closeNode(fh)
	errno = 0
	return
}

func (fs *AESFS) Opendir(path string) (errno int, fh uint64) {
	var err error
	defer Trace(path)(&err, &errno, &fh)

	errno, err, fh = fs.openNode(path, true)
	if err != nil {
		errno = -fuse.EIO
	}
	return
}

type Filler = func(name string, stat *fuse.Stat_t, offset int64) bool

func (fs *AESFS) Readdir(path string, fill Filler, offset int64, fh uint64) (errno int) {
	var err error
	defer Trace(path, offset, fh)(&err, &errno)

	var nodeObject *Node
	_, nodeObject, errno, err = fs.getNodeByPath(path, fh)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}

	stat := statDecorateForGet(nodeObject.Stat)
	fill(".", &stat, 0)
	fill("..", nil, 0)

	for name, child := range nodeObject.Children {
		var childNode *Node
		childNode, err = fs.getNode(child)
		if err != nil {
			log.WithFields(log.Fields{
				"name":  name,
				"error": err,
			}).Error("Failed to read children")
			continue
		}

		stat := statDecorateForGet(childNode.Stat)
		if !fill(name, &stat, 0) {
			break
		}
	}

	return
}

func (fs *AESFS) Releasedir(path string, fh uint64) (errno int) {
	var err error
	defer Trace(path, fh)(&err, &errno)

	fs.closeNode(fh)
	errno = 0
	return
}

// func (fs *AESFS) Setxattr(path string, name string, value []byte, flags int) (errno int) {
// 	var err error
// 	defer Trace(path, name, value, flags)(&err, &errno)

// 	var (
// 		node       NodeID
// 		nodeObject *Node
// 	)
// 	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
// 	if errno < 0 || err != nil {
// 		if err != nil {
// 			errno = -fuse.EIO
// 		}
// 		return
// 	}
// 	if node == INVALID_INO {
// 		errno = -fuse.ENOENT
// 		return
// 	}

// 	if name == "com.apple.ResourceFork" {
// 		errno = -fuse.ENOTSUP
// 		return
// 	}
// 	if flags == fuse.XATTR_CREATE {
// 		if _, exist := nodeObject.XAttr[name]; exist {
// 			return -fuse.EEXIST
// 		}
// 	} else if flags == fuse.XATTR_REPLACE {
// 		if _, exist := nodeObject.XAttr[name]; !exist {
// 			return -fuse.ENOATTR
// 		}
// 	}

// 	xattr := make([]byte, len(value))
// 	copy(xattr, value)
// 	nodeObject.XAttr[name] = xattr

// 	// dump
// 	fs.writeToCache(node, nodeObject, true)

// 	return
// }

// func (fs *AESFS) Getxattr(path string, name string) (errno int, xattr []byte) {
// 	var err error
// 	defer Trace(path, name)(&err, &errno, &xattr)

// 	var (
// 		node       NodeID
// 		nodeObject *Node
// 	)
// 	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
// 	if errno < 0 || err != nil {
// 		if err != nil {
// 			errno = -fuse.EIO
// 		}
// 		return
// 	}
// 	if node == INVALID_INO {
// 		errno = -fuse.ENOENT
// 		return
// 	}

// 	if name == "com.apple.ResourceFork" {
// 		errno = -fuse.ENOTSUP
// 		return
// 	}
// 	var exist bool
// 	xattr, exist = nodeObject.XAttr[name]
// 	if !exist {
// 		errno = -fuse.ENOATTR
// 		return
// 	}

// 	return
// }

// func (fs *AESFS) Removexattr(path string, name string) (errno int) {
// 	var err error
// 	defer Trace(path, name)(&err, &errno)

// 	var (
// 		node       NodeID
// 		nodeObject *Node
// 	)
// 	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
// 	if errno < 0 || err != nil {
// 		if err != nil {
// 			errno = -fuse.EIO
// 		}
// 		return
// 	}
// 	if node == INVALID_INO {
// 		errno = -fuse.ENOENT
// 		return
// 	}

// 	if name == "com.apple.ResourceFork" {
// 		errno = -fuse.ENOTSUP
// 		return
// 	}
// 	var exist bool
// 	_, exist = nodeObject.XAttr[name]
// 	if !exist {
// 		errno = -fuse.ENOATTR
// 		return
// 	}

// 	delete(nodeObject.XAttr, name)

// 	// dump
// 	fs.writeToCache(node, nodeObject, true)

// 	return
// }

// func (fs *AESFS) Listxattr(path string, fill func(name string) bool) (errno int) {
// 	var err error
// 	defer Trace(path)(&err, &errno)

// 	var (
// 		node       NodeID
// 		nodeObject *Node
// 	)
// 	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
// 	if errno < 0 || err != nil {
// 		if err != nil {
// 			errno = -fuse.EIO
// 		}
// 		return
// 	}
// 	if node == INVALID_INO {
// 		errno = -fuse.ENOENT
// 		return
// 	}

// 	for name := range nodeObject.XAttr {
// 		if !fill(name) {
// 			errno = -fuse.ERANGE
// 			return
// 		}
// 	}

// 	return
// }

func (fs *AESFS) Chflags(path string, flags uint32) (errno int) {
	var err error
	defer Trace(path, flags)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	nodeObject.Stat.Flags = flags
	nodeObject.Stat.Ctim = fuse.Now()

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Setcrtime(path string, timestamp fuse.Timespec) (errno int) {
	var err error
	defer Trace(path, timestamp)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	nodeObject.Stat.Birthtim = timestamp
	nodeObject.Stat.Ctim = fuse.Now()

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}

func (fs *AESFS) Setchgtime(path string, timestamp fuse.Timespec) (errno int) {
	var err error
	defer Trace(path, timestamp)(&err, &errno)

	var (
		node       NodeID
		nodeObject *Node
	)
	_, _, node, nodeObject, errno, err = fs.lookupNode(path, INVALID_INO)
	if errno < 0 || err != nil {
		if err != nil {
			errno = -fuse.EIO
		}
		return
	}
	if node == INVALID_INO {
		errno = -fuse.ENOENT
		return
	}

	nodeObject.Stat.Ctim = timestamp

	// dump
	fs.writeToCache(node, nodeObject, true)

	return
}
