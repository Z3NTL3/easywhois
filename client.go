package easywhois

import (
	"context"
	"time"

	"github.com/Z3NTL3/easywhois/utils"
	whoisparser "github.com/likexian/whois-parser"
)

type WhoisResult whoisparser.WhoisInfo
type LookupClient struct {
	Domain string // Example: "pix4.dev"
}

func (client LookupClient) Request(ctx context.Context, timeout time.Duration) (*WhoisResult, error) {
	dummy := new(WhoisResult)
	whois := new(utils.WhoisContext)
	{
		whois.Server = "whois.iana.org"
		whois.Port = 43
	}

	done := make(chan *whoisparser.WhoisInfo)
	
	defer close(done)
   	go whois.Whois(client.Domain, timeout, done)
	
	select {
		case <-ctx.Done():
			return dummy, ctx.Err()
		case V := <-done:
			whois.Server = V.Domain.WhoisServer

			// Reverse lookup against the parent responsible whois server
			go whois.Whois(client.Domain, timeout, done)
			res := <-done
			return (*WhoisResult)(res), nil
	}
}