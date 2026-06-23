package cmd

import (
	"reflect"
	"testing"

	"github.com/retlehs/quien/internal/mail"
)

func TestMXHosts(t *testing.T) {
	got := mxHosts([]mail.MXRecord{
		{Host: "alt1.aspmx.l.google.com", Priority: 1},
		{Host: "alt2.aspmx.l.google.com", Priority: 5},
	})
	want := []string{"alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mxHosts() = %v, want %v", got, want)
	}

	if got := mxHosts(nil); len(got) != 0 {
		t.Errorf("mxHosts(nil) = %v, want empty", got)
	}
}
