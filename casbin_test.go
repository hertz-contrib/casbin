// Copyright 2023 CloudWeGo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casbin

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
)

const (
	modelFile       = "./example/config/model.conf"
	simplePolicy    = "./example/config/policy.csv"
	readWritePolicy = "./example/config/policy_read_write.csv"
	userAdminPolicy = "./example/config/policy_user_admin.csv"
)

var (
	LookupAlice = func(ctx context.Context, c *app.RequestContext) string { return "alice" }
	LookupNil   = func(ctx context.Context, c *app.RequestContext) string { return "" }
)

func TestNewAuthMiddleware(t *testing.T) {
	table := []struct {
		lookup      LookupHandler
		expectedErr error
	}{
		{
			lookup:      nil,
			expectedErr: errLookupNil,
		},
		{
			lookup:      LookupAlice,
			expectedErr: nil,
		},
	}

	for _, entry := range table {
		_, err := NewCasbinMiddleware(modelFile, simplePolicy, entry.lookup)
		assert.DeepEqual(t, entry.expectedErr, err)
	}
}

func TestRequiresPermissions(t *testing.T) {
	tests := []struct {
		policyFile   string
		lookup       LookupHandler
		permissions  []string
		logic        Logic
		expectedCode int
	}{
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:read"},
			logic:        AND,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:read"},
			logic:        OR,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   readWritePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:read", "book:write"},
			logic:        AND,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   readWritePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:read", "book:write"},
			logic:        OR,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupNil,
			permissions:  []string{"book:read"},
			logic:        AND,
			expectedCode: http.StatusUnauthorized,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:write"},
			logic:        AND,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:write"},
			logic:        OR,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:read", "book:write"},
			logic:        AND,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"book:review", "book:write"},
			logic:        OR,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"readbook"},
			logic:        AND,
			expectedCode: http.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{":"},
			logic:        AND,
			expectedCode: http.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{"readbook"},
			logic:        OR,
			expectedCode: http.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			permissions:  []string{":"},
			logic:        OR,
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.lookup)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresPermissions(tt.permissions, WithLogic(tt.logic)))

		rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

		assert.DeepEqual(t, tt.expectedCode, rsp.Code)
	}
}

func TestRequiresRoles(t *testing.T) {
	tests := []struct {
		policyFile   string
		lookup       LookupHandler
		roles        []string
		logic        Logic
		expectedCode int
	}{
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			roles:        []string{"user"},
			logic:        AND,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			roles:        []string{"user"},
			logic:        OR,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   userAdminPolicy,
			lookup:       LookupAlice,
			roles:        []string{"user", "admin"},
			logic:        AND,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   userAdminPolicy,
			lookup:       LookupAlice,
			roles:        []string{"user", "admin"},
			logic:        OR,
			expectedCode: http.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupNil,
			roles:        []string{"user"},
			logic:        AND,
			expectedCode: http.StatusUnauthorized,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			roles:        []string{"admin"},
			logic:        AND,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			roles:        []string{"admin"},
			logic:        OR,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			roles:        []string{"user", "admin"},
			logic:        AND,
			expectedCode: http.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			roles:        []string{"root", "admin"},
			logic:        OR,
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.lookup)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresRoles(tt.roles, WithLogic(tt.logic)))

		rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

		assert.DeepEqual(t, tt.expectedCode, rsp.Code)
	}
}

func TestOption(t *testing.T) {
	tests := []struct {
		policyFile         string
		lookup             LookupHandler
		roles              []string
		logic              Logic
		expectedCode       int
		expectedTestHeader string
	}{
		{
			policyFile:         simplePolicy,
			lookup:             LookupNil,
			roles:              []string{"user"},
			logic:              AND,
			expectedCode:       http.StatusUnauthorized,
			expectedTestHeader: "StatusUnauthorized",
		},
		{
			policyFile:         simplePolicy,
			lookup:             LookupAlice,
			roles:              []string{"admin"},
			logic:              AND,
			expectedCode:       http.StatusForbidden,
			expectedTestHeader: "StatusForbidden",
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.lookup)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresRoles(tt.roles, WithLogic(tt.logic),
			WithForbidden(func(c context.Context, ctx *app.RequestContext) {
				ctx.Header("test", "StatusForbidden")
				ctx.AbortWithStatus(http.StatusForbidden)
			}),
			WithUnauthorized(func(c context.Context, ctx *app.RequestContext) {
				ctx.Header("test", "StatusUnauthorized")
				ctx.AbortWithStatus(http.StatusUnauthorized)
			}),
		))

		rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

		assert.DeepEqual(t, tt.expectedCode, rsp.Code)
		assert.DeepEqual(t, tt.expectedTestHeader, rsp.Header().Get("test"))
	}
}

func setupRouter(casbinMiddleware app.HandlerFunc) *server.Hertz {
	r := server.Default()

	r.GET("/book", casbinMiddleware, func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "success")
	})

	return r
}
