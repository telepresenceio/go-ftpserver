// Package server: confinedFs is an afero.Fs backed by one or more *os.Root values, confining
// every path -- however it is spelled, however many symlinks it crosses -- to a fixed set of
// directory trees: basePath (the tree the FTP client sees as its root) and, optionally, one or
// more resolveRoots. A symlink found anywhere under basePath is followed only when its literal,
// unresolved target text names basePath or one of resolveRoots (or a path under one of them);
// any other target -- including one that would otherwise resolve back inside an allowed root
// by way of ".." segments the kernel would happily walk -- is refused rather than followed. With
// no resolveRoots, only basePath itself qualifies: confinement then reduces to "nothing outside
// basePath is ever reachable", which is what os.Root already guarantees on its own.
//
// This mirrors the *os.Root-based confinement in
// cmd/traffic/cmd/agent/sftpserver/server.go's resolve/resolveLink/underMounts, generalized from
// a fixed two-root (exports, mounts) layout to an arbitrary basePath plus N resolveRoots, and
// from a single fixed symlink position (container/top) to a symlink at any depth.
package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/telepresenceio/clog"
)

// maxRedirectHops bounds the number of allowed-root redirects (or, when flattening a Readdir
// entry, the number of "target is itself a symlink" hops) resolution will chase before giving
// up. It matches the symlink-loop limit os/root.go applies to its own internal resolution.
const maxRedirectHops = 8

// namedRoot pairs an open *os.Root with the absolute, cleaned form of the directory it was
// opened on. dir is never derived from a runtime realpath/symlink resolution -- only from the
// directory name the caller passed in -- so it can be compared, as plain text, against the
// literal text of a symlink's target without introducing a TOCTOU window: the comparison never
// itself walks the filesystem, and every subsequent filesystem access goes through root, which
// is kernel-enforced.
type namedRoot struct {
	root *os.Root
	dir  string
}

// confinedFs is an afero.Fs confined to self (basePath) and extra (resolveRoots). self and every
// entry of extra are long-lived: opened once by newConfinedFs and shared by every client
// connection the driver serves, closed only when the driver itself is torn down.
type confinedFs struct {
	ctx     context.Context
	self    namedRoot
	extra   []namedRoot
	allowed []namedRoot // self followed by extra; every symlink target is checked against this
}

// newConfinedFs opens basePath and every entry of resolveRoots as an *os.Root and returns a
// confinedFs that confines all resolution to them. On error, any roots already opened are
// closed.
func newConfinedFs(ctx context.Context, basePath string, resolveRoots []string) (*confinedFs, error) {
	self, err := openNamedRoot(basePath)
	if err != nil {
		return nil, err
	}
	cf := &confinedFs{ctx: ctx, self: self, allowed: []namedRoot{self}}
	for _, rr := range resolveRoots {
		nr, err := openNamedRoot(rr)
		if err != nil {
			cf.Close()
			return nil, err
		}
		cf.extra = append(cf.extra, nr)
		cf.allowed = append(cf.allowed, nr)
	}
	return cf, nil
}

func openNamedRoot(dir string) (namedRoot, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return namedRoot{}, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		_ = root.Close()
		return namedRoot{}, err
	}
	return namedRoot{root: root, dir: path.Clean(filepath.ToSlash(abs))}, nil
}

// Close closes every *os.Root this confinedFs holds. It is called once, when the server that
// owns this confinedFs shuts down; individual client connections share these roots and never
// close them.
func (cf *confinedFs) Close() error {
	var firstErr error
	if cf.self.root != nil {
		firstErr = cf.self.root.Close()
	}
	for _, e := range cf.extra {
		if err := e.root.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (cf *confinedFs) Name() string {
	return cf.self.root.Name()
}

// resolved is the result of resolving a client-facing path: rel names the resolved entry within
// root. If owned is true, root was opened by this resolution (via os.Root.OpenRoot) and must be
// closed via close once the caller is done with it; if false, root is one of confinedFs's
// long-lived, shared roots and must never be closed.
type resolved struct {
	root  *os.Root
	rel   string
	owned bool
}

func (r *resolved) close() {
	if r.owned {
		_ = r.root.Close()
	}
}

// splitRel cleans p as an absolute path (so any ".." it contains can only cancel out an earlier
// component of p itself, never escape past the root) and splits it into components relative to
// that root. The root itself ("/", "", or anything that cleans down to "/") splits to nil.
func splitRel(p string) []string {
	clean := path.Clean("/" + p)
	if clean == "/" {
		return nil
	}
	return strings.Split(clean[1:], "/")
}

// readAbsoluteSymlink Lstats rel within root and, if it names a symlink whose literal target
// text is an absolute path, returns that text and true. Anything else -- rel doesn't exist, rel
// isn't a symlink, or rel is a symlink with a relative target -- reports ok=false with a nil
// error: a relative target is left for a native call on root to resolve (it either stays safely
// within root, which os.Root permits on its own, or tries to escape, which os.Root refuses on
// its own), and a missing entry is left for the caller's real operation to report as such.
func (cf *confinedFs) readAbsoluteSymlink(root *os.Root, rel string) (target string, ok bool, err error) {
	info, err := root.Lstat(rel)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false, nil
	}
	target, err = root.Readlink(rel)
	if err != nil {
		return "", false, err
	}
	if !path.IsAbs(target) {
		return "", false, nil
	}
	return target, true, nil
}

// matchAllowedRoot reports whether target -- the literal text of a symlink -- names one of
// cf.allowed's directories, or a path under one of them, and if so returns that root and the
// part of target relative to it ("." if target names the root's directory itself).
func (cf *confinedFs) matchAllowedRoot(target string) (*os.Root, string, bool) {
	clean := path.Clean(target)
	for _, e := range cf.allowed {
		if clean == e.dir {
			return e.root, ".", true
		}
		if rel, ok := strings.CutPrefix(clean, e.dir+"/"); ok {
			return e.root, rel, true
		}
	}
	return nil, "", false
}

// walkDirs resolves as many of dirs as exist, starting at start (an already-open root; owned
// controls whether *this call* closes start when it moves past it -- callers that still need
// start afterwards, e.g. to resolve a sibling path, pass owned=false and are responsible for
// closing it themselves once truly done). Each component is descended via os.Root.OpenRoot,
// except one whose literal, Lstat-confirmed symlink target is absolute: that one is redirected
// through matchAllowedRoot instead, refused with os.ErrPermission if no allowed root claims it.
//
// walkDirs stops early, without error, at the first component that doesn't exist (n < len(dirs)):
// callers resolving an existing path treat that as "not found"; MkdirAll treats it as "create
// the rest". Any other failure (e.g. a component exists but isn't a directory) is a genuine
// error and is always returned immediately.
func (cf *confinedFs) walkDirs(start *os.Root, owned bool, dirs []string) (root *os.Root, resultOwned bool, n int, err error) {
	cur, curOwned := start, owned
	for i, comp := range dirs {
		target, ok, rerr := cf.readAbsoluteSymlink(cur, comp)
		if rerr != nil {
			if curOwned {
				_ = cur.Close()
			}
			return nil, false, 0, rerr
		}
		if ok {
			newRoot, newRel, allowed := cf.matchAllowedRoot(target)
			if curOwned {
				_ = cur.Close()
			}
			if !allowed {
				return nil, false, 0, os.ErrPermission
			}
			if newRel == "." {
				cur, curOwned = newRoot, false
			} else {
				nr, oerr := newRoot.OpenRoot(newRel)
				if oerr != nil {
					return nil, false, 0, oerr
				}
				cur, curOwned = nr, true
			}
			continue
		}
		nr, oerr := cur.OpenRoot(comp)
		if oerr != nil {
			if errors.Is(oerr, os.ErrNotExist) {
				return cur, curOwned, i, nil
			}
			if curOwned {
				_ = cur.Close()
			}
			return nil, false, 0, oerr
		}
		if curOwned {
			_ = cur.Close()
		}
		cur, curOwned = nr, true
	}
	return cur, curOwned, len(dirs), nil
}

// resolve maps a client-facing path to the root and root-relative name that serve it. Every
// directory component is always redirect-checked (a symlink under basePath that leads into an
// allowed resolveRoot is transparent, whether it's an intermediate component or the whole
// prefix). followLeaf additionally controls the final component: true dereferences it exactly
// like the directory components (Stat, Open and friends must see through a symlink leaf);
// false leaves it alone, symlink or not, for operations that act on the entry itself (Remove,
// Mkdir, and the source/destination names of Rename).
func (cf *confinedFs) resolve(name string, followLeaf bool) (*resolved, error) {
	parts := splitRel(name)
	if len(parts) == 0 {
		return &resolved{root: cf.self.root, rel: "."}, nil
	}
	dirs, leaf := parts[:len(parts)-1], parts[len(parts)-1]
	root, owned, n, err := cf.walkDirs(cf.self.root, false, dirs)
	if err != nil {
		return nil, err
	}
	if n != len(dirs) {
		if owned {
			_ = root.Close()
		}
		return nil, os.ErrNotExist
	}
	if !followLeaf {
		return &resolved{root: root, rel: leaf, owned: owned}, nil
	}
	for hops := 0; hops < maxRedirectHops; hops++ {
		target, ok, rerr := cf.readAbsoluteSymlink(root, leaf)
		if rerr != nil {
			if owned {
				_ = root.Close()
			}
			return nil, rerr
		}
		if !ok {
			return &resolved{root: root, rel: leaf, owned: owned}, nil
		}
		newRoot, newRel, allowed := cf.matchAllowedRoot(target)
		if owned {
			_ = root.Close()
		}
		if !allowed {
			return nil, os.ErrPermission
		}
		if newRel == "." {
			return &resolved{root: newRoot, rel: "."}, nil
		}
		subParts := strings.Split(newRel, "/")
		subDirs, subLeaf := subParts[:len(subParts)-1], subParts[len(subParts)-1]
		r2, o2, n2, werr := cf.walkDirs(newRoot, false, subDirs)
		if werr != nil {
			return nil, werr
		}
		if n2 != len(subDirs) {
			if o2 {
				_ = r2.Close()
			}
			return nil, os.ErrNotExist
		}
		root, owned, leaf = r2, o2, subLeaf
	}
	if owned {
		_ = root.Close()
	}
	return nil, fmt.Errorf("ftpserver: too many nested symlinks resolving %q", name)
}

// statThroughSymlink resolves rel (an entry known to be a symlink, found directly under root)
// for Readdir flattening: it follows a chain of absolute-target redirects through the allowed
// roots, then Stats whatever it lands on, letting a native call resolve any remaining relative
// symlinks. ok is false -- with no error -- whenever the chain doesn't end up inside an allowed
// root or the final Stat fails for any other reason; the caller drops such an entry rather than
// failing the whole directory listing.
func (cf *confinedFs) statThroughSymlink(root *os.Root, rel string) (os.FileInfo, bool) {
	for hops := 0; hops < maxRedirectHops; hops++ {
		target, ok, err := cf.readAbsoluteSymlink(root, rel)
		if err != nil {
			return nil, false
		}
		if !ok {
			info, serr := root.Stat(rel)
			if serr != nil {
				return nil, false
			}
			return info, true
		}
		newRoot, newRel, allowed := cf.matchAllowedRoot(target)
		if !allowed {
			return nil, false
		}
		root, rel = newRoot, newRel
	}
	return nil, false
}

// commonPrefixLen returns the number of leading elements a and b share.
func commonPrefixLen(a, b []string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

func (cf *confinedFs) Stat(name string) (os.FileInfo, error) {
	r, err := cf.resolve(name, true)
	if err != nil {
		return nil, err
	}
	defer r.close()
	return r.root.Stat(r.rel)
}

func (cf *confinedFs) Open(name string) (afero.File, error) {
	return cf.OpenFile(name, os.O_RDONLY, 0)
}

func (cf *confinedFs) Create(name string) (afero.File, error) {
	return cf.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (cf *confinedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	r, err := cf.resolve(name, true)
	if err != nil {
		return nil, err
	}
	f, err := r.root.OpenFile(r.rel, flag, perm)
	if err != nil {
		r.close()
		return nil, err
	}
	return &confinedFile{File: f, cf: cf, root: r.root, rel: r.rel, owned: r.owned}, nil
}

func (cf *confinedFs) Mkdir(name string, perm os.FileMode) error {
	r, err := cf.resolve(name, false)
	if err != nil {
		return err
	}
	defer r.close()
	return r.root.Mkdir(r.rel, perm)
}

func (cf *confinedFs) MkdirAll(name string, perm os.FileMode) error {
	parts := splitRel(name)
	if len(parts) == 0 {
		return nil
	}
	root, owned, n, err := cf.walkDirs(cf.self.root, false, parts)
	if err != nil {
		return err
	}
	defer func() {
		if owned {
			_ = root.Close()
		}
	}()
	if n == len(parts) {
		return nil
	}
	rest := strings.Join(parts[n:], "/")
	return root.MkdirAll(rest, perm)
}

func (cf *confinedFs) Remove(name string) error {
	r, err := cf.resolve(name, false)
	if err != nil {
		return err
	}
	defer r.close()
	return r.root.Remove(r.rel)
}

func (cf *confinedFs) RemoveAll(name string) error {
	r, err := cf.resolve(name, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer r.close()
	return r.root.RemoveAll(r.rel)
}

func (cf *confinedFs) Rename(oldname, newname string) error {
	oldParts, newParts := splitRel(oldname), splitRel(newname)
	if len(oldParts) == 0 || len(newParts) == 0 {
		return os.ErrInvalid
	}
	oldDirs, oldLeaf := oldParts[:len(oldParts)-1], oldParts[len(oldParts)-1]
	newDirs, newLeaf := newParts[:len(newParts)-1], newParts[len(newParts)-1]
	common := commonPrefixLen(oldDirs, newDirs)

	root, owned, n, err := cf.walkDirs(cf.self.root, false, oldDirs[:common])
	if err != nil {
		return err
	}
	if n != common {
		if owned {
			_ = root.Close()
		}
		return os.ErrNotExist
	}
	defer func() {
		if owned {
			_ = root.Close()
		}
	}()

	rootOld, ownedOld, nOld, err := cf.walkDirs(root, false, oldDirs[common:])
	if err != nil {
		return err
	}
	if nOld != len(oldDirs)-common {
		if ownedOld {
			_ = rootOld.Close()
		}
		return os.ErrNotExist
	}
	defer func() {
		if ownedOld {
			_ = rootOld.Close()
		}
	}()

	rootNew, ownedNew, nNew, err := cf.walkDirs(root, false, newDirs[common:])
	if err != nil {
		return err
	}
	if nNew != len(newDirs)-common {
		if ownedNew {
			_ = rootNew.Close()
		}
		return os.ErrNotExist
	}
	defer func() {
		if ownedNew {
			_ = rootNew.Close()
		}
	}()

	if rootOld != rootNew {
		return fmt.Errorf("ftpserver: cannot rename %q to %q across confined roots", oldname, newname)
	}
	return rootOld.Rename(oldLeaf, newLeaf)
}

func (cf *confinedFs) Chmod(name string, mode os.FileMode) error {
	r, err := cf.resolve(name, true)
	if err != nil {
		return err
	}
	defer r.close()
	return r.root.Chmod(r.rel, mode)
}

func (cf *confinedFs) Chown(name string, uid, gid int) error {
	r, err := cf.resolve(name, true)
	if err != nil {
		return err
	}
	defer r.close()
	return r.root.Chown(r.rel, uid, gid)
}

func (cf *confinedFs) Chtimes(name string, atime, mtime time.Time) error {
	r, err := cf.resolve(name, true)
	if err != nil {
		return err
	}
	defer r.close()
	return r.root.Chtimes(r.rel, atime, mtime)
}

// confinedFile wraps the *os.File returned by an *os.Root so that Readdir flattens symlink
// entries exactly as the confinedFs that produced it would resolve them, and so that a
// transient root opened solely to reach this file (owned) is closed together with it.
type confinedFile struct {
	*os.File
	cf    *confinedFs
	root  *os.Root
	rel   string
	owned bool
}

func (f *confinedFile) Close() error {
	err := f.File.Close()
	if f.owned {
		if cerr := f.root.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// renamedFileInfo overrides Name() so a flattened Readdir entry keeps displaying the symlink's
// own name rather than whatever the resolved target happens to be named.
type renamedFileInfo struct {
	os.FileInfo
	name string
}

func (fi *renamedFileInfo) Name() string { return fi.name }

// Readdir implements afero.File's Readdir by replacing every symlink entry with the Stat of
// its resolved target -- following it through an allowed resolveRoot when its target is
// absolute, same as any other path -- under its own original name. An entry whose target
// doesn't resolve inside an allowed root (a hostile symlink planted inside served content, or
// simply a dangling one) is dropped, with a warning, rather than failing the whole listing.
func (f *confinedFile) Readdir(count int) ([]os.FileInfo, error) {
	entries, err := f.File.Readdir(count) //nolint:forbidigo // reimplementing to flatten/drop symlinks
	if err != nil {
		return nil, err
	}
	out := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		if e.Mode()&os.ModeSymlink == 0 {
			out = append(out, e)
			continue
		}
		childRel := path.Join(f.rel, e.Name())
		info, ok := f.cf.statThroughSymlink(f.root, childRel)
		if !ok {
			clog.Warnf(f.cf.ctx, "ftpserver: omitting %q from directory listing: symlink does not resolve within an allowed root", childRel)
			continue
		}
		out = append(out, &renamedFileInfo{FileInfo: info, name: e.Name()})
	}
	return out, nil
}
