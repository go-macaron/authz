Macaron-authz [![GoDoc](https://godoc.org/github.com/casbin/chi-authz?status.svg)](https://godoc.org/github.com/casbin/chi-authz)
======

Macaron-authz is an authorization middleware for [Macaron](https://github.com/go-macaron/macaron), it's based on [https://github.com/casbin/casbin](https://github.com/casbin/casbin).

## Installation

    go get github.com/casbin/macaron-authz

## Simple Example

```Go
package main

import (
	"net/http"

	"github.com/casbin/casbin"
	"github.com/casbin/macaron-authz"
	"gopkg.in/macaron.v1"
)

func main() {
	m := macaron.New()

	// load the casbin model and policy from files, database is also supported.
	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	m.Use(authz.Authorizer(e))

	// define your handler, this is just an example to return HTTP 200 for any requests.
	// the access that is denied by authz will return HTTP 403 error.
	m.Use(func(res http.ResponseWriter, req *http.Request) {
    	res.Write([]byte("Access allowed. "))
    })
}
```

## Getting Help

- [casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
