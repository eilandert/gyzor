package main

import (
	"fmt"
	"io"
	"os"

	"github.com/eilandert/gyzor/pyzor"
)

// runGenkey prints a fresh "salt,key" pair in the reference `pyzor genkey`
// format. The key (with a username) is what the pyzord administrator needs; the
// salt stays on the client. An optional passphrase is read from GYZOR_PASSPHRASE
// — empty means a fully random key (recommended). It never touches disk; use
// `gyzor register` to also save the pair locally.
func runGenkey(stdout, stderr io.Writer) int {
	salt, key, err := pyzor.GenKey(os.Getenv("GYZOR_PASSPHRASE"))
	if err != nil {
		fmt.Fprintln(stderr, "genkey:", err)
		return 1
	}
	fmt.Fprintln(stdout, "salt,key:")
	fmt.Fprintf(stdout, "%s,%s\n", salt, key)
	return 0
}

// runRegister saves an account identity into the homedir accounts file for
// every configured server, so later check/report/revoke runs sign with it
// automatically. It needs a --user. The key/salt are taken from --key/--salt
// when given (persist an admin-issued key); otherwise a fresh pair is generated
// (from GYZOR_PASSPHRASE if set, else random) and printed so the key can be
// handed to the pyzord administrator.
func runRegister(homedir string, servers []pyzor.Server, user, key, salt string, stdout, stderr io.Writer) int {
	if user == "" {
		fmt.Fprintln(stderr, "register: --user/GYZOR_USER is required")
		return 2
	}

	generated := key == ""
	if generated {
		var err error
		salt, key, err = pyzor.GenKey(os.Getenv("GYZOR_PASSPHRASE"))
		if err != nil {
			fmt.Fprintln(stderr, "register:", err)
			return 1
		}
	}

	acc := pyzor.Account{Username: user, Salt: salt, Key: key}
	path, err := pyzor.SaveAccount(homedir, servers, acc)
	if err != nil {
		fmt.Fprintln(stderr, "register:", err)
		return 1
	}

	fmt.Fprintf(stdout, "register: saved account %q for %d server(s) to %s\n", user, len(servers), path)

	// Emit the identity as environment-variable assignments so it can be used
	// via the env (a container/systemd EnvironmentFile) instead of the accounts
	// file. Bare KEY=value lines (no prefix) so `grep '^GYZOR_'` extracts them.
	fmt.Fprintln(stdout, "register: environment variables for this identity (use instead of the file):")
	fmt.Fprintf(stdout, "GYZOR_USER=%s\n", user)
	fmt.Fprintf(stdout, "GYZOR_SALT=%s\n", salt)
	fmt.Fprintf(stdout, "GYZOR_KEY=%s\n", key)

	if generated {
		// The administrator needs the username + key (not the salt) to enable
		// the account server-side.
		fmt.Fprintln(stdout, "register: give this username and key to the pyzord administrator:")
		fmt.Fprintf(stdout, "register:   user=%s key=%s\n", user, key)
	}
	return 0
}
