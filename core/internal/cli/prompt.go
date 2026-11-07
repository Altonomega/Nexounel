package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// readLine reads one line from the App's stdin, trimmed of trailing
// whitespace. It returns io.EOF when the input is closed.
func (a *App) readLine() (string, error) {
	// A fresh reader per call would lose buffered input; the App owns
	// one buffered reader for its whole lifetime.
	if a.reader == nil {
		a.reader = bufio.NewReader(a.in)
	}
	line, err := a.reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

// prompt prints a prompt and reads one line.
func (a *App) prompt(label string) (string, error) {
	fmt.Fprint(a.out, label)
	return a.readLine()
}

// confirm asks a yes/no question. It returns true only for an explicit
// "y" or "yes" (case-insensitive). Anything else, including an empty
// answer or EOF, is false.
func (a *App) confirm(label string) bool {
	answer, err := a.prompt(label + " [y/N] ")
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// confirmYes is the destructive-action gate: the operator must type
// the word "yes" in full. Anything else aborts the action.
func (a *App) confirmYes(what string) bool {
	fmt.Fprintf(a.out, "This will %s.\n", what)
	answer, err := a.prompt("Type 'yes' to confirm, anything else to abort: ")
	if err != nil {
		return false
	}
	return strings.TrimSpace(answer) == "yes"
}

// readPassword reads a password with echo disabled when stdin is a
// terminal. When stdin is not a terminal (piped input, tests) it
// reads one plain line. The password is never echoed or logged.
func (a *App) readPassword(label string) (string, error) {
	fmt.Fprint(a.out, label)
	if f, ok := a.in.(*os.File); ok {
		return readPasswordTerminal(f)
	}
	return a.readLine()
}

// readPasswordTerminal reads one line from a terminal with echo off.
// The terminal state is always restored.
func readPasswordTerminal(f *os.File) (string, error) {
	fd := int(f.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		// Not a terminal after all: plain line read.
		reader := bufio.NewReader(f)
		line, rerr := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), rerr
	}
	newState := *oldState
	newState.Lflag &^= unix.ECHO
	newState.Lflag |= unix.ICANON | unix.ISIG
	newState.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &newState); err != nil {
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, oldState) }()
	reader := bufio.NewReader(f)
	line, err := reader.ReadString('\n')
	fmt.Fprint(os.Stdout, "\n")
	return strings.TrimRight(line, "\r\n"), err
}

// readPort prompts for a TCP port and validates it (1-65535).
func (a *App) readPort(label string) (int, error) {
	answer, err := a.prompt(label)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q: must be a number between 1 and 65535", answer)
	}
	return port, nil
}

// readChoice reads a menu choice: a number, or an empty line (treated
// as "no choice"). It returns -1 for anything that is not a number.
func (a *App) readChoice() int {
	line, err := a.readLine()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0 // closed input exits the menu like choice 0
		}
		return -1
	}
	if line == "" {
		return -1
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return -1
	}
	return n
}
