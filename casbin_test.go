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
	type args struct {
		lookup      LookupHandler
		expectedErr error
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "nil lookup handler",
			args: args{
				lookup:      nil,
				expectedErr: errLookupNil,
			},
		},
		{
			name: "success",
			args: args{
				lookup:      LookupAlice,
				expectedErr: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCasbinMiddleware(modelFile, simplePolicy, tt.args.lookup)
			assert.DeepEqual(t, tt.args.expectedErr, err)
		})
	}
}

func TestRequiresPermissionsWithLogicAnd(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read",
				logic:        AND,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "nil expression",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "",
				logic:        AND,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "not existed permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:write",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "input exist and not exist permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read book:write",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "wrong permission format",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "readbook",
				logic:        AND,
				expectedCode: consts.StatusInternalServerError,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresPermissions(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestRequiresPermissionsWithLogicOr(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read",
				logic:        OR,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "nil expression",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "",
				logic:        OR,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "not existed permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:write",
				logic:        OR,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "input exist and not exist permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read book:write",
				logic:        OR,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "wrong permission format",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "readbook",
				logic:        OR,
				expectedCode: consts.StatusInternalServerError,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresPermissions(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestRequiresPermissionsWithAction(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have read permission",
			args: args{
				policyFile:   readWritePolicy,
				lookup:       LookupAlice,
				expression:   "book:read",
				logic:        AND,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "have write expression",
			args: args{
				policyFile:   readWritePolicy,
				lookup:       LookupAlice,
				expression:   "book:write",
				logic:        AND,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "have not modify permission",
			args: args{
				policyFile:   readWritePolicy,
				lookup:       LookupAlice,
				expression:   "book:modify",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "input two exist permissions",
			args: args{
				policyFile:   readWritePolicy,
				lookup:       LookupAlice,
				expression:   "book:read book:write",
				logic:        AND,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "input exist and not exist permission",
			args: args{
				policyFile:   readWritePolicy,
				lookup:       LookupAlice,
				expression:   "book:read book:modify",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresPermissions(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestRequiresPermissionsWithLogicCustom(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read",
				logic:        CUSTOM,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "nil expression",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "",
				logic:        CUSTOM,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "not existed permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:write",
				logic:        CUSTOM,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "test \"&&\"",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read && book:write",
				logic:        CUSTOM,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "test \"&&\"",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "book:read || book:write",
				logic:        CUSTOM,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "test \"!\"",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "!book:read",
				logic:        CUSTOM,
				expectedCode: consts.StatusForbidden,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresPermissions(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestRequiresRolesWithLogicAnd(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have role",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupNil,
				expression:   "user",
				logic:        AND,
				expectedCode: consts.StatusUnauthorized,
			},
		},
		{
			name: "not existed role",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "admin",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "input exist and not exist permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "user admin",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "have roles",
			args: args{
				policyFile:   userAdminPolicy,
				lookup:       LookupAlice,
				expression:   "user admin",
				logic:        AND,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "not existed role2",
			args: args{
				policyFile:   userAdminPolicy,
				lookup:       LookupAlice,
				expression:   "user admin root",
				logic:        AND,
				expectedCode: consts.StatusForbidden,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresRoles(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestRequiresRolesWithLogicOr(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have role",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "user",
				logic:        OR,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "not existed role",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "admin",
				logic:        OR,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "input exist and not exist permission",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "root admin",
				logic:        OR,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "have roles",
			args: args{
				policyFile:   userAdminPolicy,
				lookup:       LookupAlice,
				expression:   "user admin",
				logic:        OR,
				expectedCode: consts.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresRoles(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestRequiresRolesWithLogicCustom(t *testing.T) {
	type args struct {
		policyFile   string
		lookup       LookupHandler
		expression   string
		logic        Logic
		expectedCode int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "have role",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "user",
				logic:        CUSTOM,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "test \"||\"",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "user || admin",
				logic:        CUSTOM,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "test \"&&\"",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "user && admin",
				logic:        CUSTOM,
				expectedCode: consts.StatusForbidden,
			},
		},
		{
			name: "test \"!\"",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "user && !admin",
				logic:        CUSTOM,
				expectedCode: consts.StatusOK,
			},
		},
		{
			name: "not existed role",
			args: args{
				policyFile:   simplePolicy,
				lookup:       LookupAlice,
				expression:   "admin",
				logic:        CUSTOM,
				expectedCode: consts.StatusForbidden,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresRoles(tt.args.expression, WithLogic(tt.args.logic)))

			rsp := ut.PerformRequest(r.Engine, "GET", "/book", nil)

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
		})
	}
}

func TestOption(t *testing.T) {
	// Test default logic
	opts := NewOptions()
	assert.DeepEqual(t, opts.Logic, AND)

	type args struct {
		policyFile         string
		lookup             LookupHandler
		expression         string
		logic              Logic
		expectedCode       int
		expectedTestHeader string
	}
	// Test WithFunc
	tests := []struct {
		name string
		args args
	}{
		{
			name: "1",
			args: args{
				policyFile:         simplePolicy,
				lookup:             LookupNil,
				expression:         "book-read",
				logic:              AND,
				expectedCode:       consts.StatusUnauthorized,
				expectedTestHeader: "StatusUnauthorized",
			},
		},
		{
			name: "2",
			args: args{
				policyFile:         simplePolicy,
				lookup:             LookupAlice,
				expression:         "book-write",
				logic:              AND,
				expectedCode:       consts.StatusForbidden,
				expectedTestHeader: "StatusForbidden",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewCasbinMiddleware(modelFile, tt.args.policyFile, tt.args.lookup)
			if err != nil {
				t.Fatal(err)
			}

			r := setupRouter(middleware.RequiresPermissions(tt.args.expression, WithLogic(tt.args.logic),
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

			assert.DeepEqual(t, tt.args.expectedCode, rsp.Code)
			assert.DeepEqual(t, tt.args.expectedTestHeader, rsp.Header().Get("test"))
		})
	}
}

func setupRouter(casbinMiddleware app.HandlerFunc) *server.Hertz {
	r := server.Default()

	r.GET("/book", casbinMiddleware, func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "success")
	})

	return r
}
