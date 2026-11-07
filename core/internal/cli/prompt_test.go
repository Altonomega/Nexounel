package cli

import (
	"strings"
	"testing"
)

func TestConfirm(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"y\n", true},
		{"yes\n", true},
		{"Y\n", true},
		{"YES\n", true},
		{"n\n", false},
		{"no\n", false},
		{"\n", false},
		{"maybe\n", false},
	}
	for _, c := range cases {
		app, _ := newTestApp(t, "/tmp/x", "/tmp/y")
		app.in = strings.NewReader(c.input)
		if got := app.confirm("Proceed?"); got != c.want {
			t.Errorf("confirm(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestConfirmYes(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"yes\n", true},
		{"y\n", false}, // "y" is not enough: the word must be "yes"
		{"YES\n", false},
		{"no\n", false},
		{"\n", false},
	}
	for _, c := range cases {
		app, _ := newTestApp(t, "/tmp/x", "/tmp/y")
		app.in = strings.NewReader(c.input)
		if got := app.confirmYes("delete everything"); got != c.want {
			t.Errorf("confirmYes(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestReadPort(t *testing.T) {
	cases := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"18081\n", 18081, false},
		{"1\n", 1, false},
		{"65535\n", 65535, false},
		{"0\n", 0, true},
		{"65536\n", 0, true},
		{"abc\n", 0, true},
		{"-1\n", 0, true},
		{"\n", 0, true},
	}
	for _, c := range cases {
		app, _ := newTestApp(t, "/tmp/x", "/tmp/y")
		app.in = strings.NewReader(c.input)
		got, err := app.readPort("Port: ")
		if c.wantErr {
			if err == nil {
				t.Errorf("readPort(%q): expected error, got %d", c.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("readPort(%q): unexpected error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("readPort(%q) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestReadChoice(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"0\n", 0},
		{"16\n", 16},
		{"abc\n", -1},
		{"\n", -1},
		{"", 0}, // closed input exits like choice 0
	}
	for _, c := range cases {
		app, _ := newTestApp(t, "/tmp/x", "/tmp/y")
		app.in = strings.NewReader(c.input)
		if got := app.readChoice(); got != c.want {
			t.Errorf("readChoice(%q) = %d, want %d", c.input, got, c.want)
		}
	}
}
