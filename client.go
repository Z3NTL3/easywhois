package easywhois

import (
	"context"
	"time"

	"github.com/Z3NTL3/easywhois/utils"
	whoisparser "github.com/likexian/whois-parser"
)

type WhoisResult *whoisparser.WhoisInfo
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

	res, err := whois.Whois(client.Domain, timeout)
	if err != nil {
		return dummy, err
	}
	whois.Server = res.Domain.WhoisServer

	// Reverse lookup against the parent responsible whois server
	res, err = whois.Whois(client.Domain, timeout)
	if err != nil {
		return dummy, err
	}
	return (*WhoisResult)(&res), nil
}