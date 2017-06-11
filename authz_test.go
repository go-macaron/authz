package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin"
	"gopkg.in/macaron.v1"
)

func testAuthzRequest(t *testing.T, m *macaron.Macaron, user string, path string, method string, code int) {
	r, _ := http.NewRequest(method, path, nil)
	r.SetBasicAuth(user, "123")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	if w.Code != code {
		t.Errorf("%s, %s, %s: %d, supposed to be %d", user, path, method, w.Code, code)
	}
}

func TestBasic(t *testing.T) {
	m := macaron.New()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	m.Use(Authorizer(e))

	// Here we use HTTP basic authentication as the way to get the logged-in user name
	// For simplicity, the credential is not verified, you should implement and use your own
	// authentication before the authorization.
	// In this example, we assume "alice:123" is a legal user.
	m.Use(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("Access allowed. "))
	})

	testAuthzRequest(t, m, "alice", "/dataset1/resource1", "GET", 200)
	testAuthzRequest(t, m, "alice", "/dataset1/resource1", "POST", 200)
	testAuthzRequest(t, m, "alice", "/dataset1/resource2", "GET", 200)
	testAuthzRequest(t, m, "alice", "/dataset1/resource2", "POST", 403)
}

func TestPathWildcard(t *testing.T) {
	m := macaron.New()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	m.Use(Authorizer(e))

	// Here we use HTTP basic authentication as the way to get the logged-in user name
	// For simplicity, the credential is not verified, you should implement and use your own
	// authentication before the authorization.
	// In this example, we assume "alice:123" is a legal user.
	m.Use(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("Access allowed. "))
	})

	testAuthzRequest(t, m, "bob", "/dataset2/resource1", "GET", 200)
	testAuthzRequest(t, m, "bob", "/dataset2/resource1", "POST", 200)
	testAuthzRequest(t, m, "bob", "/dataset2/resource1", "DELETE", 200)
	testAuthzRequest(t, m, "bob", "/dataset2/resource2", "GET", 200)
	testAuthzRequest(t, m, "bob", "/dataset2/resource2", "POST", 403)
	testAuthzRequest(t, m, "bob", "/dataset2/resource2", "DELETE", 403)

	testAuthzRequest(t, m, "bob", "/dataset2/folder1/item1", "GET", 403)
	testAuthzRequest(t, m, "bob", "/dataset2/folder1/item1", "POST", 200)
	testAuthzRequest(t, m, "bob", "/dataset2/folder1/item1", "DELETE", 403)
	testAuthzRequest(t, m, "bob", "/dataset2/folder1/item2", "GET", 403)
	testAuthzRequest(t, m, "bob", "/dataset2/folder1/item2", "POST", 200)
	testAuthzRequest(t, m, "bob", "/dataset2/folder1/item2", "DELETE", 403)
}

func TestRBAC(t *testing.T) {
	m := macaron.New()

	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	m.Use(Authorizer(e))

	// Here we use HTTP basic authentication as the way to get the logged-in user name
	// For simplicity, the credential is not verified, you should implement and use your own
	// authentication before the authorization.
	// In this example, we assume "alice:123" is a legal user.
	m.Use(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("Access allowed. "))
	})

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testAuthzRequest(t, m, "cathy", "/dataset1/item", "GET", 200)
	testAuthzRequest(t, m, "cathy", "/dataset1/item", "POST", 200)
	testAuthzRequest(t, m, "cathy", "/dataset1/item", "DELETE", 200)
	testAuthzRequest(t, m, "cathy", "/dataset2/item", "GET", 403)
	testAuthzRequest(t, m, "cathy", "/dataset2/item", "POST", 403)
	testAuthzRequest(t, m, "cathy", "/dataset2/item", "DELETE", 403)

	// delete all roles on user cathy, so cathy cannot access any resources now.
	e.DeleteRolesForUser("cathy")

	testAuthzRequest(t, m, "cathy", "/dataset1/item", "GET", 403)
	testAuthzRequest(t, m, "cathy", "/dataset1/item", "POST", 403)
	testAuthzRequest(t, m, "cathy", "/dataset1/item", "DELETE", 403)
	testAuthzRequest(t, m, "cathy", "/dataset2/item", "GET", 403)
	testAuthzRequest(t, m, "cathy", "/dataset2/item", "POST", 403)
	testAuthzRequest(t, m, "cathy", "/dataset2/item", "DELETE", 403)
}
