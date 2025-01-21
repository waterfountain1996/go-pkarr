package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/waterfountain1996/go-pkarr"
	"golang.org/x/net/dns/dnsmessage"
)

var z32 = base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769").WithPadding(base32.NoPadding)

func main() {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	m := dnsmessage.Message{
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
	}
	record, err := pkarr.New(priv, m, time.Now())
	if err != nil {
		panic(err)
	}

	relayURL, _ := url.Parse("https://relay.pkarr.org")
	if err := put(relayURL, record); err != nil {
		panic(err)
	}

	fmt.Println("Your key:", z32.EncodeToString(record.PublicKey()))
}

func put(relayURL *url.URL, record pkarr.Record) error {
	u := relayURL.JoinPath(z32.EncodeToString(record.PublicKey()))
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(record.Payload()))
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		return fmt.Errorf("got unsuccesful response: %s", res.Status)
	}
	return nil
}
