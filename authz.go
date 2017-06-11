package authz

// This plugin is based on Casbin: an authorization library that supports ACL, RBAC, ABAC
// View source at:
// https://github.com/casbin/casbin

import (
	"net/http"

	"github.com/casbin/casbin"
	"gopkg.in/macaron.v1"
)

// Authz is a middleware that controls the access to the HTTP service, it is based
// on Casbin, which supports access control models like ACL, RBAC, ABAC.
// The plugin determines whether to allow a request based on (user, path, method).
// user: the authenticated user name.
// path: the URL for the requested resource.
// method: one of HTTP methods like GET, POST, PUT, DELETE.
//
// This middleware should be inserted fairly early in the middleware stack to
// protect subsequent layers. All the denied requests will not go further.
//
// It's notable that this middleware should be behind the authentication (e.g.,
// HTTP basic authentication, OAuth), so this plugin can get the logged-in user name
// to perform the authorization.

// Authorizer returns a Casbin authorizer Handler.
func Authorizer(e *casbin.Enforcer) macaron.Handler {
	return func(res http.ResponseWriter, req *http.Request, c *macaron.Context) {
		user, _, _ := req.BasicAuth()
		method := req.Method
		path := req.URL.Path
		if !e.Enforce(user, path, method) {
			accessDenied(res)
			return
		}
	}
}

func accessDenied(res http.ResponseWriter) {
	http.Error(res, "Access Denied", http.StatusForbidden)
}
