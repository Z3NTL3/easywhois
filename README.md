# EasyWhois
A Go module for wrapping WHOIS data within ease.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Z3NTL3/easywhois"
)


func main(){
	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancel()
	
	client := new(easywhois.LookupClient)
	client.Domain = "pix4.dev"

	whois, err := client.Request(ctx, time.Second * 5); if err != nil {
		fmt.Println(err)
		return
	}
	
	fmt.Println(whois.Registrar.Name)
	fmt.Println(whois.Domain.ExpirationDate)
	// etc
}
```
# Author
- Z3NTL3
