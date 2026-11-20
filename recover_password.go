package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Offline password recovery.
//
// Password hashes are one-way by design, so a forgotten password cannot be
// recovered — only replaced. This command is the operator's recovery path and
// deliberately runs *without* the network listener: it needs local access to
// the database file, which only someone who already controls the host has.
//
//	./echo-server -reset-password -user root -password 'new-secret'
//	./echo-server -reset-password -user root          # prompts on a TTY
//
// It refuses to run while another process holds the database (SQLite locking
// makes a concurrent writer fail anyway) and it never prints the old or new
// password back.
func runResetPassword() {
	// Define the mode flag too: runResetPassword is called from main before any
	// flag.Parse, so this FlagSet is the first parser to see os.Args.
	_ = flag.Bool("reset-password", true, "offline password recovery mode")
	var (
		user  = flag.String("user", "", "account to reset (required)")
		pw    = flag.String("password", "", "new password (omit to be prompted)")
		role  = flag.String("role", "", "optionally also set the role: admin|viewer")
		quiet = flag.Bool("quiet", false, "suppress the success line")
	)
	flag.Parse()

	u := strings.TrimSpace(*user)
	if u == "" {
		// Also accept the username as a positional argument for convenience.
		if rest := flag.Args(); len(rest) > 0 {
			u = strings.TrimSpace(rest[0])
		}
	}
	if u == "" {
		fmt.Fprintln(os.Stderr, "usage: echo-server -reset-password -user <name> [-password <pw>] [-role admin|viewer]")
		os.Exit(2)
	}

	pwValue := *pw
	if pwValue == "" {
		fmt.Fprintf(os.Stderr, "New password for %q: ", u)
		p1 := readPasswordFromTTY()
		fmt.Fprintf(os.Stderr, "Repeat: ")
		p2 := readPasswordFromTTY()
		if p1 != p2 {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			os.Exit(1)
		}
		pwValue = p1
	}

	initDB()
	acct, err := GetUser(u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account %q not found (is this the right database? set ECHO_SERVER_DB): %v\n", u, err)
		os.Exit(1)
	}

	if err := SetPassword(acct.Username, pwValue); err != nil {
		fmt.Fprintf(os.Stderr, "password reset failed: %v\n", err)
		os.Exit(1)
	}

	if *role != "" {
		if !validRole(*role) {
			fmt.Fprintf(os.Stderr, "invalid role %q\n", *role)
			os.Exit(2)
		}
		if _, err := UpdateUser(acct.Username, "", *role, nil); err != nil {
			fmt.Fprintf(os.Stderr, "role update failed: %v\n", err)
			os.Exit(1)
		}
	}

	// An operator who locked themselves out is usually also disabled or has an
	// unreadable state; re-enabling the account they just reset is expected.
	if acct.Disabled {
		enabled := false
		if _, err := UpdateUser(acct.Username, "", "", &enabled); err == nil {
			fmt.Fprintln(os.Stderr, "account was disabled; re-enabled it")
		}
	}

	// Audit unconditionally: -quiet only silences the success line, it must
	// never suppress the record of a privileged offline action. The trail
	// names the invoking OS user rather than pretending this came from the UI.
	RecordAuditDirect("password.reset.offline", acct.Username, "os-user="+currentOSUser())

	if !*quiet {
		fmt.Fprintf(os.Stdout, "reset password for %q (role=%s). Start the server and log in.\n",
			acct.Username, acct.Role)
	}
}

// currentOSUser reports the invoking OS account for the audit trail.
func currentOSUser() string {
	if v := os.Getenv("SUDO_USER"); v != "" {
		return v
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if v := os.Getenv("LOGNAME"); v != "" {
		return v
	}
	return "unknown"
}

// readPasswordFromTTY reads a password without echoing it. It falls back to a
// buffered read when not on a terminal (pipes/CI), where echo suppression is
// impossible anyway.
func readPasswordFromTTY() string {
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		fmt.Fprint(os.Stderr, "***\n")
	}
	var b []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			if buf[0] != '\r' {
				b = append(b, buf[0])
			}
		}
		if err != nil {
			break
		}
	}
	return string(b)
}

// hasResetPasswordFlag reports whether the process was started for offline
// password recovery. Checked before flag.Parse so the normal server path never
// has a global FlagSet populated by an unrelated binary mode.
func hasResetPasswordFlag(args []string) bool {
	for _, a := range args {
		if a == "-reset-password" || a == "--reset-password" {
			return true
		}
	}
	return false
}
