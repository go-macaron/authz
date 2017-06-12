Macaron-authz [![Build Status](https://travis-ci.org/go-macaron/authz.svg?branch=master)](https://travis-ci.org/go-macaron/authz) [![Coverage Status](https://coveralls.io/repos/github/go-macaron/authz/badge.svg?branch=master)](https://coveralls.io/github/go-macaron/authz?branch=master) [![GoDoc](https://godoc.org/github.com/go-macaron/authz?status.svg)](https://godoc.org/github.com/go-macaron/authz)
======

Macaron-authz is an authorization middleware for [Macaron](https://github.com/go-macaron/macaron), it's based on [https://github.com/casbin/casbin](https://github.com/casbin/casbin).

## Installation

    go get github.com/go-macaron/authz

## Simple Example

```Go
package main

import (
	"net/http"

	"github.com/casbin/casbin"
	"github.com/go-macaron/authz"
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

## How to control the access

The authorization determines a request based on ``{subject, object, action}``, which means what ``subject`` can perform what ``action`` on what ``object``. In this plugin, the meanings are:

1. ``subject``: the logged-on user name
2. ``object``: the URL path for the web resource like "dataset1/item1"
3. ``action``: HTTP method like GET, POST, PUT, DELETE, or the high-level actions you defined like "read-file", "write-blog"

For how to write authorization policy and other details, please refer to [the Casbin's documentation](https://github.com/casbin/casbin).

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
