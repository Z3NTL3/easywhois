package utils

import (
	"fmt"
	"net"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

type WhoisContext struct {
	Server string
	Port int
}

func (c WhoisContext) Whois(
	domain string, timeout time.Duration, done chan <-*whoisparser.WhoisInfo,
){
	dummy := new(whoisparser.WhoisInfo)
	conn, err := net.DialTimeout(
		"tcp",
		fmt.Sprintf("%s:%d", c.Server, c.Port),
		timeout,
	)
	if err != nil {
		done <- dummy
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(
		timeout,
	)
	conn.SetDeadline(deadline)

	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		done <- dummy
		return
	}

	data := make([]byte, 0)
	buffer := make([]byte, 1042)

	for {
		rLen, err := conn.Read(buffer)
		if err != nil {
			break
		}

		if rLen <= 0 {
			break
		}

		data = append(data, buffer...)
	}

	whois, err := whoisparser.Parse(string(data))
	if err != nil {
		done <- dummy
		return
	}

	done <- &whois
	return
}