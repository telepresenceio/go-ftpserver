package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"testing"
	"time"
)

// TestAuthUserUnknownUserDoesNotPanic reproduces the historical operator-precedence bug where a
// map miss (ok == false, user == nil) fell through to a nil pointer dereference. Against the old
// AuthUser this test panics instead of failing cleanly.
func TestAuthUserUnknownUserDoesNotPanic(t *testing.T) {
	d := &driver{
		ctx: context.Background(),
		users: map[string]*user{
			"anonymous": {password: "*", basePath: "/"},
		},
	}
	if _, err := d.AuthUser(nil, "nosuchuser", "whatever"); err == nil {
		t.Fatal("expected an error for an unknown user, got nil")
	}
}

func TestAuthUserAnonymous(t *testing.T) {
	d := &driver{
		ctx: context.Background(),
		users: map[string]*user{
			"anonymous": {password: "*", basePath: "/"},
		},
	}
	if _, err := d.AuthUser(nil, "anonymous", "password-one"); err != nil {
		t.Fatalf("expected anonymous login to succeed, got %v", err)
	}
	if _, err := d.AuthUser(nil, "anonymous", "password-two"); err != nil {
		t.Fatalf("expected anonymous login to succeed with a different password, got %v", err)
	}
	if _, err := d.AuthUser(nil, "somebody-else", "whatever"); err == nil {
		t.Fatal("expected login for an unknown user to fail")
	}
}

func TestAuthUserValidator(t *testing.T) {
	var gotUserName, gotPassword string
	errRejected := errors.New("rejected")
	d := &driver{
		ctx:      context.Background(),
		basePath: "/",
		validate: func(_ context.Context, userName, password string) error {
			gotUserName, gotPassword = userName, password
			if userName == "bob" && password == "s3cret" {
				return nil
			}
			return errRejected
		},
	}

	cd, err := d.AuthUser(nil, "bob", "s3cret")
	if err != nil {
		t.Fatalf("expected accepted login, got %v", err)
	}
	if cd == nil {
		t.Fatal("expected a non-nil ClientDriver on success")
	}
	if gotUserName != "bob" || gotPassword != "s3cret" {
		t.Fatalf("validator received (%q, %q), want (%q, %q)", gotUserName, gotPassword, "bob", "s3cret")
	}

	cd, err = d.AuthUser(nil, "bob", "wrong")
	if !errors.Is(err, errRejected) {
		t.Fatalf("expected rejection error %v, got %v", errRejected, err)
	}
	if cd != nil {
		t.Fatal("expected a nil ClientDriver on rejection")
	}
}

// startAnonymousTestServer starts a real FTP server on an ephemeral loopback port using the
// anonymous Start entry point and returns its address. The server is stopped via t.Cleanup.
func startAnonymousTestServer(t *testing.T, basePath string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	portCh := make(chan uint16, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Start(ctx, "127.0.0.1", basePath, portCh)
	}()
	return waitForTestServer(t, cancel, portCh, errCh)
}

// startValidatorTestServer is like startAnonymousTestServer, but authenticates using validate.
func startValidatorTestServer(t *testing.T, basePath string, validate PasswordValidator) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	portCh := make(chan uint16, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- StartWithValidator(ctx, "127.0.0.1", basePath, portCh, validate)
	}()
	return waitForTestServer(t, cancel, portCh, errCh)
}

func waitForTestServer(t *testing.T, cancel context.CancelFunc, portCh <-chan uint16, errCh <-chan error) string {
	t.Helper()
	port, ok := <-portCh
	if !ok {
		cancel()
		t.Fatalf("server failed to start: %v", <-errCh)
	}
	t.Cleanup(func() {
		cancel()
		if err := <-errCh; err != nil {
			t.Errorf("server returned an error after being stopped: %v", err)
		}
	})
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// ftpLogin dials addr and performs a USER/PASS login round-trip, returning the code of the PASS
// response (230 on success, 530 on rejection).
func ftpLogin(t *testing.T, addr, userName, password string) int {
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
	if err := tp.PrintfLine("USER %s", userName); err != nil {
		t.Fatalf("send USER: %v", err)
	}
	if _, _, err := tp.ReadResponse(0); err != nil {
		t.Fatalf("read USER response: %v", err)
	}
	if err := tp.PrintfLine("PASS %s", password); err != nil {
		t.Fatalf("send PASS: %v", err)
	}
	code, _, err := tp.ReadResponse(0)
	if err != nil {
		t.Fatalf("read PASS response: %v", err)
	}
	_ = tp.PrintfLine("QUIT")
	return code
}

func TestEndToEndAnonymous(t *testing.T) {
	addr := startAnonymousTestServer(t, t.TempDir())

	if code := ftpLogin(t, addr, "anonymous", "does-not-matter"); code != 230 {
		t.Fatalf("anonymous login: got code %d, want 230", code)
	}
	if code := ftpLogin(t, addr, "someone-else", "does-not-matter"); code != 530 {
		t.Fatalf("unknown user login: got code %d, want 530", code)
	}
}

func TestEndToEndValidator(t *testing.T) {
	validate := func(_ context.Context, userName, password string) error {
		if userName == "carol" && password == "swordfish" {
			return nil
		}
		return errors.New("invalid credentials")
	}
	addr := startValidatorTestServer(t, t.TempDir(), validate)

	if code := ftpLogin(t, addr, "carol", "swordfish"); code != 230 {
		t.Fatalf("validator login: got code %d, want 230", code)
	}
	if code := ftpLogin(t, addr, "carol", "wrong-password"); code != 530 {
		t.Fatalf("validator rejection: got code %d, want 530", code)
	}
}
