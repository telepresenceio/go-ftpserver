package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// confinementFixture models the layout the traffic-agent produces: a "mounts" tree (what
// kubelet actually writes to disk, addressed by resolveRoots) and an "exports" tree (what the
// agent publishes as basePath, an absolute symlink per container into the matching mounts
// subtree). It also plants the hostile symlinks and unexported content a confined filesystem
// must refuse.
type confinementFixture struct {
	mounts  string // resolveRoot: the real, kubelet-written tree
	exports string // basePath: what the FTP client sees as its root
	c       string // container name, the top-level directory under both trees

	// content is the known content of the kubelet-style file reachable at
	// /<c>/etc/rtest-config/f.conf through the export symlink and the relative ..data chain.
	content string

	plainFileContent string // content of the plain file directly under exports
	plainDirContent  string // content of the file inside the plain directory under exports
}

const fixtureContainer = "c1"

func newConfinementFixture(t *testing.T) confinementFixture {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("confinement fixture relies on os.Root symlink-confinement semantics verified on linux")
	}

	mounts := t.TempDir()
	exports := t.TempDir()
	c := fixtureContainer
	const content = "rtest-config-known-content\n"
	const plainFileContent = "plain-file-content\n"
	const plainDirContent = "plain-dir-content\n"

	// mounts/<c>/etc/rtest-config/: kubelet-style relative symlink chain.
	dataDir := filepath.Join(mounts, c, "etc", "rtest-config", "..2026_data")
	mustMkdirAll(t, dataDir)
	mustWriteFile(t, filepath.Join(dataDir, "f.conf"), content)
	rtestConfigDir := filepath.Join(mounts, c, "etc", "rtest-config")
	mustSymlink(t, "..2026_data", filepath.Join(rtestConfigDir, "..data"))
	mustSymlink(t, "..data/f.conf", filepath.Join(rtestConfigDir, "f.conf"))

	// mounts/<c>/etc/escape: hostile absolute symlink planted inside mounted content.
	mustSymlink(t, "/etc/passwd", filepath.Join(mounts, c, "etc", "escape"))

	// mounts/<c>/secret/...: an unexported top -- no matching symlink will exist in exports.
	secretDir := filepath.Join(mounts, c, "secret")
	mustMkdirAll(t, secretDir)
	mustWriteFile(t, filepath.Join(secretDir, "topsecret.txt"), "do-not-serve\n")

	// exports/<c>/etc -> mounts/<c>/etc: the absolute symlink the agent creates.
	mustMkdirAll(t, filepath.Join(exports, c))
	mustSymlink(t, filepath.Join(mounts, c, "etc"), filepath.Join(exports, c, "etc"))

	// exports/<c>/evil -> /etc: hostile absolute symlink planted directly in exports.
	mustSymlink(t, "/etc", filepath.Join(exports, c, "evil"))

	// plain, non-symlink content directly under exports.
	mustWriteFile(t, filepath.Join(exports, "plainfile.txt"), plainFileContent)
	mustMkdirAll(t, filepath.Join(exports, "plaindir"))
	mustWriteFile(t, filepath.Join(exports, "plaindir", "inner.txt"), plainDirContent)

	return confinementFixture{
		mounts:           mounts,
		exports:          exports,
		c:                c,
		content:          content,
		plainFileContent: plainFileContent,
		plainDirContent:  plainDirContent,
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
}

func mustWriteFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", name, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", link, target, err)
	}
}

// newFixtureConfinedFs opens a confinedFs rooted at basePath with the given resolveRoots and
// arranges for it to be closed at the end of the test.
func newFixtureConfinedFs(t *testing.T, basePath string, resolveRoots ...string) *confinedFs {
	t.Helper()
	cf, err := newConfinedFs(context.Background(), basePath, resolveRoots)
	if err != nil {
		t.Fatalf("newConfinedFs(%q, %v): %v", basePath, resolveRoots, err)
	}
	t.Cleanup(func() { _ = cf.Close() })
	return cf
}

func entryNames(entries []os.FileInfo) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

func containsName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// TestConfinedFsReadThroughExportLinkAndKubeletChain covers required assertion 1: reading
// /<c>/etc/rtest-config/f.conf must resolve through the absolute exports->mounts symlink and
// then through the relative kubelet-style ..data chain, landing on the real file's content.
func TestConfinedFsReadThroughExportLinkAndKubeletChain(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	p := path.Join("/", fx.c, "etc", "rtest-config", "f.conf")
	fi, err := cf.Stat(p)
	if err != nil {
		t.Fatalf("Stat(%q): %v", p, err)
	}
	if fi.IsDir() {
		t.Fatalf("Stat(%q): got a directory, want a regular file", p)
	}

	f, err := cf.Open(p)
	if err != nil {
		t.Fatalf("Open(%q): %v", p, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading %q: %v", p, err)
	}
	if string(data) != fx.content {
		t.Fatalf("Open(%q) content = %q, want %q", p, data, fx.content)
	}
}

// TestConfinedFsReaddirEtcDropsHostileEscapeSymlink covers half of required assertion 2:
// listing /<c>/etc must succeed, keep the legitimate "rtest-config" entry, and drop the hostile
// "escape" symlink rather than failing the whole listing.
func TestConfinedFsReaddirEtcDropsHostileEscapeSymlink(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	dirPath := path.Join("/", fx.c, "etc")
	d, err := cf.Open(dirPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", dirPath, err)
	}
	defer d.Close()
	entries, err := d.Readdir(-1)
	if err != nil {
		t.Fatalf("Readdir(%q): %v", dirPath, err)
	}
	names := entryNames(entries)
	if !containsName(names, "rtest-config") {
		t.Fatalf("Readdir(%q) = %v, want it to include %q (fixture or listing is broken)", dirPath, names, "rtest-config")
	}
	if containsName(names, "escape") {
		t.Fatalf("Readdir(%q) = %v, the hostile %q entry must be dropped from the listing", dirPath, names, "escape")
	}
}

// TestConfinedFsReaddirRtestConfigShowsFlattenedKubeletFile covers the other half of required
// assertion 2: listing the kubelet-style directory must flatten the relative ..data/f.conf
// symlink chain and show "f.conf" (plus its siblings) via a native, in-root resolution.
func TestConfinedFsReaddirRtestConfigShowsFlattenedKubeletFile(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	dirPath := path.Join("/", fx.c, "etc", "rtest-config")
	d, err := cf.Open(dirPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", dirPath, err)
	}
	defer d.Close()
	entries, err := d.Readdir(-1)
	if err != nil {
		t.Fatalf("Readdir(%q): %v", dirPath, err)
	}
	names := entryNames(entries)
	for _, want := range []string{"f.conf", "..data", "..2026_data"} {
		if !containsName(names, want) {
			t.Fatalf("Readdir(%q) = %v, want it to include %q", dirPath, names, want)
		}
	}
}

// TestConfinedFsRefusesHostileSymlinkInsideMountedContent covers required assertion 3.
func TestConfinedFsRefusesHostileSymlinkInsideMountedContent(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	// Sanity first: a legitimate sibling under the very same directory must resolve, so a
	// refusal below reflects a genuine confinement decision and not a broken fixture.
	legit := path.Join("/", fx.c, "etc", "rtest-config", "f.conf")
	if _, err := cf.Stat(legit); err != nil {
		t.Fatalf("sanity Stat(%q): %v (fixture is broken)", legit, err)
	}

	p := path.Join("/", fx.c, "etc", "escape")
	if _, err := cf.Stat(p); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Stat(%q) = %v, want an os.ErrPermission refusal (must not be served as /etc/passwd)", p, err)
	}
	if _, err := cf.Open(p); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Open(%q) = %v, want an os.ErrPermission refusal", p, err)
	}
}

// TestConfinedFsRefusesHostileExportSymlink covers required assertion 4.
func TestConfinedFsRefusesHostileExportSymlink(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	legit := path.Join("/", fx.c, "etc", "rtest-config", "f.conf")
	if _, err := cf.Stat(legit); err != nil {
		t.Fatalf("sanity Stat(%q): %v (fixture is broken)", legit, err)
	}

	evil := path.Join("/", fx.c, "evil")
	if _, err := cf.Stat(evil); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Stat(%q) = %v, want an os.ErrPermission refusal", evil, err)
	}

	evilChild := path.Join("/", fx.c, "evil", "passwd")
	if _, err := cf.Stat(evilChild); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Stat(%q) = %v, want an os.ErrPermission refusal", evilChild, err)
	}
}

// TestConfinedFsUnexportedTopNotReachable covers required assertion 5.
func TestConfinedFsUnexportedTopNotReachable(t *testing.T) {
	fx := newConfinementFixture(t)

	// Sanity: the file genuinely exists on disk in mounts.
	onDisk := filepath.Join(fx.mounts, fx.c, "secret", "topsecret.txt")
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("sanity os.Stat(%q): %v (fixture is broken)", onDisk, err)
	}

	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)
	p := path.Join("/", fx.c, "secret", "topsecret.txt")
	if _, err := cf.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(%q) = %v, want os.ErrNotExist (mounts-only \"secret\" top has no exports symlink)", p, err)
	}
}

// TestConfinedFsPathTraversalRefused covers required assertion 6.
func TestConfinedFsPathTraversalRefused(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	legit := path.Join("/", fx.c, "etc", "rtest-config", "f.conf")
	if _, err := cf.Stat(legit); err != nil {
		t.Fatalf("sanity Stat(%q): %v (fixture is broken)", legit, err)
	}

	for _, p := range []string{
		"/" + fx.c + "/../../etc/passwd",
		"/../../../../etc/passwd",
		"/" + fx.c + "/etc/../../../../etc/passwd",
	} {
		if _, err := cf.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Stat(%q) = %v, want os.ErrNotExist (.. must never escape basePath)", p, err)
		}
	}
}

// TestConfinedFsNoResolveRootsRefusesExportSymlink covers required assertion 7: the
// secure-by-default posture when no resolveRoots are configured.
func TestConfinedFsNoResolveRootsRefusesExportSymlink(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports) // no resolveRoots

	p := path.Join("/", fx.c, "etc", "rtest-config", "f.conf")
	if _, err := cf.Stat(p); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Stat(%q) with no resolveRoots = %v, want os.ErrPermission -- "+
			"see TestConfinedFsReadThroughExportLinkAndKubeletChain for the succeeding counterpart with resolveRoots set", p, err)
	}

	// Plain, non-symlinked content must still work with no resolveRoots at all.
	plain := "/plainfile.txt"
	if _, err := cf.Stat(plain); err != nil {
		t.Fatalf("Stat(%q) with no resolveRoots: %v (plain layout should be unaffected)", plain, err)
	}
}

// TestConfinedFsWriteOperationsThroughExportLinkLandInMounts covers required assertion 8:
// Create, Mkdir, Rename (within one root), Chmod, Chtimes, and Remove, all reached through the
// exports->mounts symlink, must act on the mounts tree on disk and never materialize anything
// on the exports side.
func TestConfinedFsWriteOperationsThroughExportLinkLandInMounts(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	// Create
	createPath := path.Join("/", fx.c, "etc", "rtest-config", "written.txt")
	f, err := cf.Create(createPath)
	if err != nil {
		t.Fatalf("Create(%q): %v", createPath, err)
	}
	const written = "hello from the ftp client\n"
	if _, err := f.Write([]byte(written)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mountsFile := filepath.Join(fx.mounts, fx.c, "etc", "rtest-config", "written.txt")
	data, err := os.ReadFile(mountsFile)
	if err != nil {
		t.Fatalf("the written file was not created in mounts at %q: %v", mountsFile, err)
	}
	if string(data) != written {
		t.Fatalf("mounts file content = %q, want %q", data, written)
	}

	// The exports side must be untouched: "etc" must remain the symlink it always was, not a
	// materialized directory holding a copy of the write.
	lfi, err := os.Lstat(filepath.Join(fx.exports, fx.c, "etc"))
	if err != nil {
		t.Fatalf("Lstat exports etc: %v", err)
	}
	if lfi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("exports/%s/etc is no longer a symlink after the write (mode %v)", fx.c, lfi.Mode())
	}

	// Mkdir
	mkdirPath := path.Join("/", fx.c, "etc", "rtest-config", "newdir")
	if err := cf.Mkdir(mkdirPath, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", mkdirPath, err)
	}
	mountsDir := filepath.Join(fx.mounts, fx.c, "etc", "rtest-config", "newdir")
	if fi, err := os.Stat(mountsDir); err != nil || !fi.IsDir() {
		t.Fatalf("Mkdir(%q) did not create a directory at %q: err=%v", mkdirPath, mountsDir, err)
	}

	// Rename, within the same (mounts) root
	renameFrom := path.Join("/", fx.c, "etc", "rtest-config", "written.txt")
	renameTo := path.Join("/", fx.c, "etc", "rtest-config", "renamed.txt")
	if err := cf.Rename(renameFrom, renameTo); err != nil {
		t.Fatalf("Rename(%q, %q): %v", renameFrom, renameTo, err)
	}
	if _, err := os.Stat(mountsFile); !os.IsNotExist(err) {
		t.Fatalf("old name %q still exists after rename: err=%v", mountsFile, err)
	}
	renamedMountsFile := filepath.Join(fx.mounts, fx.c, "etc", "rtest-config", "renamed.txt")
	if data, err := os.ReadFile(renamedMountsFile); err != nil || string(data) != written {
		t.Fatalf("renamed file at %q: data=%q err=%v", renamedMountsFile, data, err)
	}

	// Chmod
	if err := cf.Chmod(renameTo, 0o640); err != nil {
		t.Fatalf("Chmod(%q): %v", renameTo, err)
	}
	if fi, err := os.Stat(renamedMountsFile); err != nil || fi.Mode().Perm() != 0o640 {
		perm := os.FileMode(0)
		if fi != nil {
			perm = fi.Mode().Perm()
		}
		t.Fatalf("Chmod(%q) did not change mounts file perm: got %v, err %v", renameTo, perm, err)
	}

	// Chtimes
	wantMtime := time.Date(2021, 6, 7, 8, 9, 10, 0, time.UTC)
	wantAtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := cf.Chtimes(renameTo, wantAtime, wantMtime); err != nil {
		t.Fatalf("Chtimes(%q): %v", renameTo, err)
	}
	fi, err := os.Stat(renamedMountsFile)
	if err != nil {
		t.Fatalf("Stat after Chtimes: %v", err)
	}
	if diff := fi.ModTime().Sub(wantMtime); diff < -2*time.Second || diff > 2*time.Second {
		t.Fatalf("Chtimes(%q) mtime = %v, want ~%v", renameTo, fi.ModTime(), wantMtime)
	}

	// Remove
	if err := cf.Remove(renameTo); err != nil {
		t.Fatalf("Remove(%q): %v", renameTo, err)
	}
	if _, err := os.Stat(renamedMountsFile); !os.IsNotExist(err) {
		t.Fatalf("Remove(%q) did not remove the mounts file, err=%v", renameTo, err)
	}
}

// TestConfinedFsRenameAcrossRootsFails covers required assertion 9: renaming from a path that
// resolves into mounts (through the export symlink) to a path that resolves directly into
// exports (no symlink involved) must fail outright rather than doing something odd.
func TestConfinedFsRenameAcrossRootsFails(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	crossSrc := path.Join("/", fx.c, "etc", "rtest-config", "cross.txt")
	f, err := cf.Create(crossSrc)
	if err != nil {
		t.Fatalf("Create(%q): %v", crossSrc, err)
	}
	const content = "cross-root content\n"
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	mountsSrc := filepath.Join(fx.mounts, fx.c, "etc", "rtest-config", "cross.txt")
	if _, err := os.Stat(mountsSrc); err != nil {
		t.Fatalf("sanity: %q was not created: %v", mountsSrc, err)
	}

	crossDst := "/plain-cross-dest.txt" // resolves directly under basePath (exports), no symlink involved
	if err := cf.Rename(crossSrc, crossDst); err == nil {
		t.Fatalf("Rename(%q, %q) succeeded, want a cross-root refusal", crossSrc, crossDst)
	}

	// The source must be untouched, and no destination must have been created anywhere.
	if _, err := os.Stat(mountsSrc); err != nil {
		t.Fatalf("source %q missing after failed cross-root rename: %v", mountsSrc, err)
	}
	exportsDst := filepath.Join(fx.exports, "plain-cross-dest.txt")
	if _, err := os.Stat(exportsDst); !os.IsNotExist(err) {
		t.Fatalf("destination %q must not exist after a failed rename, err=%v", exportsDst, err)
	}
}

// TestConfinedFsPlainLayoutUnaffected covers required assertion 10: a plain file and directory
// directly under basePath, with no symlinks involved at all, must still work normally.
func TestConfinedFsPlainLayoutUnaffected(t *testing.T) {
	fx := newConfinementFixture(t)
	cf := newFixtureConfinedFs(t, fx.exports, fx.mounts)

	f, err := cf.Open("/plainfile.txt")
	if err != nil {
		t.Fatalf("Open(/plainfile.txt): %v", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading /plainfile.txt: %v", err)
	}
	if string(data) != fx.plainFileContent {
		t.Fatalf("content = %q, want %q", data, fx.plainFileContent)
	}

	d, err := cf.Open("/plaindir")
	if err != nil {
		t.Fatalf("Open(/plaindir): %v", err)
	}
	defer d.Close()
	entries, err := d.Readdir(-1)
	if err != nil {
		t.Fatalf("Readdir(/plaindir): %v", err)
	}
	if !containsName(entryNames(entries), "inner.txt") {
		t.Fatalf("Readdir(/plaindir) = %v, want it to include inner.txt", entryNames(entries))
	}
}

// startConfinedTestServer starts a real FTP server, authenticating any username with any
// password, serving basePath and confining resolution to resolveRoots. The server is stopped
// via t.Cleanup.
func startConfinedTestServer(t *testing.T, basePath string, resolveRoots ...string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	portCh := make(chan uint16, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Start(ctx, "127.0.0.1", basePath, portCh, resolveRoots...)
	}()
	return waitForTestServer(t, cancel, portCh, errCh)
}

var pasvAddrRE = regexp.MustCompile(`\((\d+,\d+,\d+,\d+,\d+,\d+)\)`)

func parsePasvAddr(t *testing.T, msg string) string {
	t.Helper()
	m := pasvAddrRE.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("could not parse PASV response %q", msg)
	}
	parts := strings.Split(m[1], ",")
	ip := strings.Join(parts[:4], ".")
	p1, err1 := strconv.Atoi(parts[4])
	p2, err2 := strconv.Atoi(parts[5])
	if err1 != nil || err2 != nil {
		t.Fatalf("could not parse PASV port from %q", msg)
	}
	return fmt.Sprintf("%s:%d", ip, p1*256+p2)
}

// ftpRetrieve dials addr, logs in, and RETRs path over a real passive-mode data connection. It
// returns the final status code and message (whatever the control channel produced -- 226 with
// data on success, or a rejection code such as 550 with no data at all when the server refuses
// the path before ever asking for a data connection).
func ftpRetrieve(t *testing.T, addr, userName, password, remotePath string) (code int, message string, data []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(0); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	cmd := func(format string, args ...any) (int, string) {
		line := fmt.Sprintf(format, args...)
		if err := tp.PrintfLine("%s", line); err != nil {
			t.Fatalf("send %s: %v", line, err)
		}
		c, m, err := tp.ReadResponse(0)
		if err != nil {
			t.Fatalf("read response to %s: %v", line, err)
		}
		return c, m
	}

	if c, m := cmd("USER %s", userName); c != 331 && c != 230 {
		t.Fatalf("USER %s: got %d %s", userName, c, m)
	}
	if c, m := cmd("PASS %s", password); c != 230 {
		t.Fatalf("PASS: got %d %s", c, m)
	}
	if c, m := cmd("TYPE I"); c != 200 {
		t.Fatalf("TYPE I: got %d %s", c, m)
	}
	pasvCode, pasvMsg := cmd("PASV")
	if pasvCode != 227 {
		t.Fatalf("PASV: got %d %s", pasvCode, pasvMsg)
	}
	dataAddr := parsePasvAddr(t, pasvMsg)
	dataConn, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial data conn %s: %v", dataAddr, err)
	}
	defer dataConn.Close()

	if err := tp.PrintfLine("RETR %s", remotePath); err != nil {
		t.Fatalf("send RETR %s: %v", remotePath, err)
	}
	code, message, err = tp.ReadResponse(0)
	if err != nil {
		t.Fatalf("read RETR response: %v", err)
	}
	if code == 150 {
		buf, rerr := io.ReadAll(dataConn)
		if rerr != nil {
			t.Fatalf("read data connection: %v", rerr)
		}
		data = buf
		code, message, err = tp.ReadResponse(0)
		if err != nil {
			t.Fatalf("read final RETR response: %v", err)
		}
	}
	_ = tp.PrintfLine("QUIT")
	return code, message, data
}

// TestEndToEndConfinementHostileSymlinkNotServedOverWire drives a real FTP client/server
// round trip (login, PASV, RETR) proving that hostile symlinks are refused over the wire, not
// merely at the confinedFs API level, while a legitimate file behind the same export symlink is
// actually retrievable.
func TestEndToEndConfinementHostileSymlinkNotServedOverWire(t *testing.T) {
	fx := newConfinementFixture(t)
	addr := startConfinedTestServer(t, fx.exports, fx.mounts)

	// Sanity/allowed case first: the legitimate file must be servable before any refusal below
	// can be trusted as a real confinement decision.
	legit := path.Join("/", fx.c, "etc", "rtest-config", "f.conf")
	code, msg, data := ftpRetrieve(t, addr, "anonymous", "whatever", legit)
	if code != 226 {
		t.Fatalf("RETR %s: got %d %s, want 226 (fixture or server wiring is broken)", legit, code, msg)
	}
	if string(data) != fx.content {
		t.Fatalf("RETR %s: got content %q, want %q", legit, data, fx.content)
	}

	for _, hostile := range []string{
		path.Join("/", fx.c, "etc", "escape"),           // hostile symlink inside mount content -> /etc/passwd
		path.Join("/", fx.c, "evil"),                    // hostile symlink in exports -> /etc
		path.Join("/", fx.c, "evil", "passwd"),          // through the hostile exports symlink
		path.Join("/", fx.c, "secret", "topsecret.txt"), // unexported top
	} {
		code, msg, data := ftpRetrieve(t, addr, "anonymous", "whatever", hostile)
		if code == 226 {
			t.Fatalf("RETR %s: served over the wire (code %d, %d bytes), want a refusal", hostile, code, len(data))
		}
		t.Logf("RETR %s correctly refused: %d %s", hostile, code, msg)
	}
}
