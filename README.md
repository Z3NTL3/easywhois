# EasyWhois
A Go module for wrapping WHOIS data within ease.

```go
// Example usage
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Z3NTL3/easywhois"
)

func main(){
	client := new(easywhois.LookupClient)
	client.Domain = "pix4.dev"

	whois, err := client.Request(context.TODO(), time.Second * 5); if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Domain: %s\r\n", whois.Domain.Domain)
	fmt.Printf("Exp: %s\r\n", whois.Domain.ExpirationDate)
	fmt.Printf("Registrar: %s\r\n", whois.Registrar.Email)
	// etc
}
```
# Author
- Z3NTL3
