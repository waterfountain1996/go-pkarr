package pkarr_test

import (
	"crypto/ed25519"
	"strconv"
	"testing"
	"time"

	"github.com/waterfountain1996/go-pkarr"
	"golang.org/x/net/dns/dnsmessage"
)

func TestRecord_PackUnpack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		m dnsmessage.Message
		t time.Time
	}{
		{
			m: dnsmessage.Message{
				Header: dnsmessage.Header{Response: true},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("_foo."),
							Type:  dnsmessage.TypeTXT,
							Class: dnsmessage.ClassINET,
							TTL:   30,
						},
						Body: &dnsmessage.TXTResource{
							TXT: []string{"bar"},
						},
					},
				},
			},
			t: time.Date(2024, time.June, 16, 13, 37, 42, 5, time.Local),
		},
	}

	for i, tt := range cases {
		t.Run("#"+strconv.Itoa(i), func(t *testing.T) {
			want, err := pkarr.New(priv, tt.m, tt.t)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if _, err := pkarr.FromPayload(pub, want.Payload()); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
