package main

import "testing"

func TestExecute(t *testing.T) {
	if err := execute([]string{"version"}); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{"unknown"}); err == nil {
		t.Fatal("unknown command was accepted")
	}
}
