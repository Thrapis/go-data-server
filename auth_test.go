package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestParseAppTokensAndLookup(t *testing.T) {
	src := "# comment\n\nalpha " + hashOf("alpha-token") + "\n  beta\t" + hashOf("beta-token") + "  \n_admin " + hashOf("admin-token") + "\n"
	tokens, err := ParseAppTokens(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]string{"alpha-token": "alpha", "beta-token": "beta", "admin-token": "_admin"} {
		if got, ok := tokens.Lookup(token); !ok || got != want {
			t.Errorf("Lookup(%q) = %q, %v; want %q", token, got, ok, want)
		}
	}
	for _, token := range []string{"", "nope", "alpha-token "} {
		if got, ok := tokens.Lookup(token); ok {
			t.Errorf("Lookup(%q) = %q, want no match", token, got)
		}
	}
	if got := strings.Join(tokens.Names(), ","); got != "alpha,beta" {
		t.Errorf("Names = %s, want alpha,beta (no _admin)", got)
	}
}

func TestParseAppTokensRejectsBadFiles(t *testing.T) {
	good := hashOf("x")
	for name, src := range map[string]string{
		"bad app name":    "Bad_App " + good,
		"reserved name":   "whoami " + good,
		"reserved name 2": "system " + good,
		"short hash":      "alpha abc123",
		"non-hex hash":    "alpha " + strings.Repeat("z", 64),
		"missing hash":    "alpha",
		"extra field":     "alpha " + good + " extra",
		"duplicate app":   "alpha " + good + "\nalpha " + hashOf("y"),
		"duplicate hash":  "alpha " + good + "\nbeta " + good,
	} {
		if _, err := ParseAppTokens(strings.NewReader(src)); err == nil {
			t.Errorf("%s: ParseAppTokens succeeded, want an error", name)
		}
	}
}

func TestNewTokenIsRandomAndHashMatches(t *testing.T) {
	a, hashA, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := newToken()
	if a == b || len(a) != 64 {
		t.Errorf("tokens %q, %q: want two distinct 64-char hex strings", a, b)
	}
	if hashA != hashOf(a) {
		t.Errorf("hash = %s, want sha256 of the token", hashA)
	}
}
