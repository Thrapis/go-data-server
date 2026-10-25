package main

import "testing"

func TestIsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9696", "localhost:9696", "[::1]:9696", "127.1.2.3:1"} {
		if !isLoopback(addr) {
			t.Errorf("isLoopback(%q) = false", addr)
		}
	}
	// Anything that could be reached from the network, including "all interfaces".
	for _, addr := range []string{"0.0.0.0:9696", ":9696", "[::]:9696", "203.0.113.5:9696", "10.9.0.1:9696", "example.com:9696", "garbage"} {
		if isLoopback(addr) {
			t.Errorf("isLoopback(%q) = true", addr)
		}
	}
}

func TestRunNewTokenRejectsBadNames(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}, {"Bad_App"}, {"whoami"}, {""}} {
		if err := runNewToken(args); err == nil {
			t.Errorf("runNewToken(%q) succeeded, want an error", args)
		}
	}
}
