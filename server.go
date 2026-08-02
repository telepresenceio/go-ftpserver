// Package server contains an FTP server based on github.com/fclairamb/ftpserverlib
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	ftp "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"

	"github.com/telepresenceio/clog"
)

type user struct {
	password string
	basePath string
}

// PasswordValidator validates a username/password pair submitted during FTP login.
// A non-nil error rejects the login.
type PasswordValidator func(ctx context.Context, user, password string) error

type driver struct {
	ftp.Settings
	sync.Mutex
	ctx      context.Context
	clients  []ftp.ClientContext
	users    map[string]*user
	basePath string
	validate PasswordValidator
	fs       *confinedFs // shared afero.Fs, confined to basePath and any resolveRoots; one per driver, reused by every connection
}

type client struct {
	afero.Fs
	ctx context.Context
}

// GetHandle implements ftpserver.ClientDriverExtentionFileTransfer
func (c *client) GetHandle(name string, flags int, offset int64) (ftp.FileTransfer, error) {
	clog.Debugf(c.ctx, "GetHandle(%s, %#x, %d)", name, flags, offset)
	f, err := c.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	if flags == os.O_CREATE|os.O_WRONLY {
		if err := f.Truncate(offset); err != nil {
			return nil, err
		}
	}
	if offset > 0 {
		_, err = f.Seek(offset, 0)
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

func newDriver(ctx context.Context, publicHost string, port uint16, portAnnounceCh chan<- uint16) (*driver, error) {
	lc := net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	a := l.Addr().(*net.TCPAddr)

	d := &driver{
		ctx: ctx,
		Settings: ftp.Settings{
			Banner:              "Telepresence Traffic Agent",
			PublicHost:          publicHost,
			DefaultTransferType: ftp.TransferTypeBinary,
			EnableHASH:          true,
			Listener:            l,
			ListenAddr:          a.String(),
			IdleTimeout:         300,
		}}

	clog.Infof(ctx, "FTP server listening on %s", d.ListenAddr)
	if portAnnounceCh != nil {
		portAnnounceCh <- uint16(a.Port)
	}
	return d, nil
}

// ClientConnected keeps track of the connected client so that it is properly closed
// if the server is stopped before a call to ClientDisconnected arrives.
func (d *driver) ClientConnected(cc ftp.ClientContext) (string, error) {
	d.Lock()
	expand := true
	for i, c := range d.clients {
		if c == nil {
			d.clients[i] = cc
			expand = false
			break
		}
	}
	if expand {
		d.clients = append(d.clients, cc)
	}
	d.Unlock()
	clog.Infof(d.ctx, "Client connected, id %d, remoteAddr %s", cc.ID(), cc.RemoteAddr())
	cc.SetDebug(clog.Enabled(d.ctx, slog.LevelDebug))
	return "telepresence", nil
}

func (d *driver) ClientDisconnected(cc ftp.ClientContext) {
	d.Lock()
	for i, c := range d.clients {
		if c != nil && c.ID() == cc.ID() {
			d.clients[i] = nil
			break
		}
	}
	d.Unlock()
	clog.Infof(d.ctx, "Client disconnected, id %d, remoteAddr %s", cc.ID(), cc.RemoteAddr())
}

func (d *driver) AuthUser(_ ftp.ClientContext, userName, password string) (ftp.ClientDriver, error) {
	if _, err := d.authenticate(userName, password); err != nil {
		return nil, err
	}
	return &client{Fs: d.fs, ctx: d.ctx}, nil
}

// authenticate validates userName/password and returns the base path to serve on success.
func (d *driver) authenticate(userName, password string) (string, error) {
	if d.validate != nil {
		if err := d.validate(d.ctx, userName, password); err != nil {
			return "", err
		}
		return d.basePath, nil
	}
	user, ok := d.users[userName]
	if !ok {
		return "", errors.New("unknown user")
	}
	if user.password != "*" && subtle.ConstantTimeCompare([]byte(user.password), []byte(password)) != 1 {
		return "", errors.New("invalid password")
	}
	return user.basePath, nil
}

func (d *driver) GetTLSConfig() (*tls.Config, error) {
	return nil, errors.New("not enabled")
}

func (d *driver) GetSettings() (*ftp.Settings, error) {
	return &d.Settings, nil
}

// StartOnPort is like Start, but listens on the given port instead of an ephemeral one.
//
// A symlink under basePath is served (rather than refused) when its target is basePath itself,
// a path under it, or a path under one of resolveRoots; with no resolveRoots, only basePath
// qualifies. See confinedFs for the full confinement semantics.
func StartOnPort(ctx context.Context, publicHost string, basePath string, port uint16, resolveRoots ...string) error {
	return start(ctx, publicHost, basePath, port, nil, resolveRoots)
}

// Start starts an FTP server serving basePath and authenticating any username with any
// password (the "anonymous" pattern). The port it bound is sent once on portAnnounceCh, which
// is then closed.
//
// A symlink under basePath is served (rather than refused) when its target is basePath itself,
// a path under it, or a path under one of resolveRoots; with no resolveRoots, only basePath
// qualifies. See confinedFs for the full confinement semantics.
func Start(ctx context.Context, publicHost string, basePath string, portAnnounceCh chan<- uint16, resolveRoots ...string) error {
	defer close(portAnnounceCh)
	return start(ctx, publicHost, basePath, 0, portAnnounceCh, resolveRoots)
}

// StartOnPortWithValidator is like StartOnPort, but authenticates logins using validate instead
// of the built-in anonymous user.
func StartOnPortWithValidator(ctx context.Context, publicHost, basePath string, port uint16, validate PasswordValidator, resolveRoots ...string) error {
	return startWithValidator(ctx, publicHost, basePath, port, nil, validate, resolveRoots)
}

// StartWithValidator is like Start, but authenticates logins using validate instead of the
// built-in anonymous user.
func StartWithValidator(ctx context.Context, publicHost, basePath string, portAnnounceCh chan<- uint16, validate PasswordValidator, resolveRoots ...string) error {
	defer close(portAnnounceCh)
	return startWithValidator(ctx, publicHost, basePath, 0, portAnnounceCh, validate, resolveRoots)
}

func start(ctx context.Context, publicHost string, basePath string, port uint16, portAnnounceCh chan<- uint16, resolveRoots []string) error {
	fs, err := newConfinedFs(ctx, basePath, resolveRoots)
	if err != nil {
		return err
	}
	d, err := newDriver(ctx, publicHost, port, portAnnounceCh)
	if err != nil {
		_ = fs.Close()
		return err
	}
	d.fs = fs
	d.users = map[string]*user{
		"anonymous": {
			password: "*",
			basePath: basePath,
		},
	}
	return serve(ctx, d)
}

func startWithValidator(ctx context.Context, publicHost, basePath string, port uint16, portAnnounceCh chan<- uint16, validate PasswordValidator, resolveRoots []string) error {
	if validate == nil {
		return errors.New("validate must not be nil")
	}
	fs, err := newConfinedFs(ctx, basePath, resolveRoots)
	if err != nil {
		return err
	}
	d, err := newDriver(ctx, publicHost, port, portAnnounceCh)
	if err != nil {
		_ = fs.Close()
		return err
	}
	d.fs = fs
	d.basePath = basePath
	d.validate = validate
	return serve(ctx, d)
}

func serve(ctx context.Context, d *driver) error {
	s := ftp.NewFtpServer(d)
	s.Logger = clog.Logger(ctx)
	go func() {
		<-ctx.Done()
		clog.Info(ctx, "Stopping FTP server")
		d.Lock()
		for _, c := range d.clients {
			if c != nil {
				c.Close()
			}
		}
		d.clients = nil
		d.Unlock()
		if err := s.Stop(); err != nil {
			clog.Errorf(ctx, "failed to stop ftp server: %v", err)
		}
	}()
	clog.Info(ctx, "Starting FTP server")
	err := s.ListenAndServe()
	if d.fs != nil {
		if cerr := d.fs.Close(); cerr != nil {
			clog.Errorf(ctx, "failed to close confined filesystem: %v", cerr)
		}
	}
	return err
}
