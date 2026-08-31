package main

import "testing"

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URI", "")
	t.Setenv("AUTH_SECRET", "")
	for _, args := range [][]string{{}, {"-unknown"}} {
		if err := run(args); err == nil {
			t.Fatalf("invalid configuration accepted: %v", args)
		}
	}
}
