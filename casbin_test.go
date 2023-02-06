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
	"github.com/cloudwego/hertz/pkg/protocol/consts"
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
		expression   string
		logic        Logic
		expectedCode int
	}{
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:read",
			logic:        AND,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:read",
			logic:        OR,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   readWritePolicy,
			lookup:       LookupAlice,
			expression:   "book:read book:write",
			logic:        AND,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   readWritePolicy,
			lookup:       LookupAlice,
			expression:   "book:read book:write",
			logic:        OR,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupNil,
			expression:   "book:read",
			logic:        AND,
			expectedCode: consts.StatusUnauthorized,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:write",
			logic:        AND,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:write",
			logic:        OR,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:read book:write",
			logic:        AND,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:review book:write",
			logic:        OR,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "readbook",
			logic:        AND,
			expectedCode: consts.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   ":",
			logic:        AND,
			expectedCode: consts.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "",
			logic:        AND,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "readbook",
			logic:        OR,
			expectedCode: consts.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   ":",
			logic:        OR,
			expectedCode: consts.StatusInternalServerError,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "",
			logic:        OR,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:read",
			logic:        CUSTOM,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:write",
			logic:        CUSTOM,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "!book:read",
			logic:        CUSTOM,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "!book:write",
			logic:        CUSTOM,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:read && book:write",
			logic:        CUSTOM,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "book:read || book:write",
			logic:        CUSTOM,
			expectedCode: consts.StatusOK,
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.lookup)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresPermissions(tt.expression, WithLogic(tt.logic)))

		rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

		assert.DeepEqual(t, tt.expectedCode, rsp.Code)
	}
}

func TestRequiresRoles(t *testing.T) {
	tests := []struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}{
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user",
			logic:        AND,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user",
			logic:        OR,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   userAdminPolicy,
			lookup:       LookupAlice,
			expression:   "user admin",
			logic:        AND,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   userAdminPolicy,
			lookup:       LookupAlice,
			expression:   "user admin",
			logic:        OR,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupNil,
			expression:   "user",
			logic:        AND,
			expectedCode: consts.StatusUnauthorized,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "admin",
			logic:        AND,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "admin",
			logic:        OR,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user admin",
			logic:        AND,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "root admin",
			logic:        OR,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user",
			logic:        CUSTOM,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "admin",
			logic:        CUSTOM,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user && admin",
			logic:        CUSTOM,
			expectedCode: consts.StatusForbidden,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user || admin",
			logic:        CUSTOM,
			expectedCode: consts.StatusOK,
		},
		{
			policyFile:   simplePolicy,
			lookup:       LookupAlice,
			expression:   "user && !admin",
			logic:        CUSTOM,
			expectedCode: consts.StatusOK,
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.lookup)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresRoles(tt.expression, WithLogic(tt.logic)))

		rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

		assert.DeepEqual(t, tt.expectedCode, rsp.Code)
	}
}

func TestOption(t *testing.T) {
	// Test default logic
	opts := NewOptions()
	assert.DeepEqual(t, opts.Logic, AND)

	// Test WithFunc
	tests := []struct {
		policyFile         string
		lookup             LookupHandler
		expression         string
		logic              Logic
		expectedCode       int
		expectedTestHeader string
	}{
		{
			policyFile:         simplePolicy,
			lookup:             LookupNil,
			expression:         "book-read",
			logic:              AND,
			expectedCode:       consts.StatusUnauthorized,
			expectedTestHeader: "StatusUnauthorized",
		},
		{
			policyFile:         simplePolicy,
			lookup:             LookupAlice,
			expression:         "book-write",
			logic:              AND,
			expectedCode:       consts.StatusForbidden,
			expectedTestHeader: "StatusForbidden",
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.lookup)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresPermissions(tt.expression, WithLogic(tt.logic),
			WithForbidden(func(c context.Context, ctx *app.RequestContext) {
				ctx.Header("test", "StatusForbidden")
				ctx.AbortWithStatus(consts.StatusForbidden)
			}),
			WithUnauthorized(func(c context.Context, ctx *app.RequestContext) {
				ctx.Header("test", "StatusUnauthorized")
				ctx.AbortWithStatus(consts.StatusUnauthorized)
			}),
			WithPermissionParser(PermissionParserWithSeparator("-")),
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
