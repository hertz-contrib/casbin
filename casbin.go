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
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/casbin/casbin/v2"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

type Middleware struct {
	// Enforcer is the main interface for authorization enforcement and policy management.
	enforcer casbin.IEnforcer
	// LookupHandler is used to look up current subject in runtime.
	// If it can not find anything, just return an empty string.
	lookup LookupHandler
}

// NewCasbinMiddleware returns a new Middleware using Casbin's Enforcer internally.
//
// modelFile is the file path to Casbin model file e.g. path/to/rbac_model.conf.
// adapter can be a file or a DB adapter.
// lookup is a function that looks up the current subject in runtime and returns an empty string if nothing found.
func NewCasbinMiddleware(modelFile string, adapter interface{}, lookup LookupHandler) (*Middleware, error) {
	e, err := casbin.NewEnforcer(modelFile, adapter)
	if err != nil {
		return nil, err
	}

	return NewCasbinMiddlewareFromEnforcer(e, lookup)
}

// NewCasbinMiddlewareFromEnforcer creates from given Enforcer.
func NewCasbinMiddlewareFromEnforcer(e casbin.IEnforcer, lookup LookupHandler) (*Middleware, error) {
	if lookup == nil {
		return nil, errLookupNil
	}

	return &Middleware{
		enforcer: e,
		lookup:   lookup,
	}, nil
}

// RequiresPermissions tries to find the current subject and determine if the
// subject has the required permissions according to predefined Casbin policies.
func (m *Middleware) RequiresPermissions(expression string, opts ...Option) app.HandlerFunc {
	// Here we provide default options.
	options := NewOptions(opts...)
	return func(ctx context.Context, c *app.RequestContext) {
		if expression == "" {
			c.Next(ctx)
			return
		}
		// Look up current subject.
		sub := m.lookup(ctx, c)
		if sub == "" {
			options.Unauthorized(ctx, c)
			return
		}
		// Enforce Casbin policies.
		if options.Logic == AND {
			// Must pass all tests.
			permissions := strings.Split(expression, " ")
			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if vals[0] == "" || vals[1] == "" {
					// Can not handle any illegal permission strings.
					c.AbortWithStatus(consts.StatusInternalServerError)
					return
				}
				if ok, err := m.enforcer.Enforce(stringSliceToInterfaceSlice(vals)...); err != nil {
					c.AbortWithStatus(consts.StatusInternalServerError)
					return
				} else if !ok {
					options.Forbidden(ctx, c)
					return
				}
			}
			c.Next(ctx)
			return
		} else if options.Logic == OR {
			// Need to pass at least one test.
			permissions := strings.Split(expression, " ")
			for _, permission := range permissions {
				values := append([]string{sub}, options.PermissionParser(permission)...)
				if values[0] == "" || values[1] == "" {
					// Can not handle any illegal permission strings.
					c.AbortWithStatus(consts.StatusInternalServerError)
					return
				}
				if ok, err := m.enforcer.Enforce(stringSliceToInterfaceSlice(values)...); err != nil {
					c.AbortWithStatus(consts.StatusInternalServerError)
					return
				} else if ok {
					c.Next(ctx)
					return
				}
			}
			options.Forbidden(ctx, c)
			return
		} else if options.Logic == CUSTOM {
			expression = strings.Replace(expression, options.PermissionSeparator, "\\"+options.PermissionSeparator, -1)
			exp, err := govaluate.NewEvaluableExpression(expression)
			if err != nil {
				c.AbortWithStatus(consts.StatusInternalServerError)
				return
			}

			permissions := exp.Vars()
			params := make(utils.H, len(permissions))

			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if vals[0] == "" || vals[1] == "" {
					// Can not handle any illegal permission strings.
					c.AbortWithStatus(consts.StatusInternalServerError)
					return
				}
				if ok, err := m.enforcer.Enforce(stringSliceToInterfaceSlice(vals)...); err != nil {
					c.AbortWithStatus(consts.StatusInternalServerError)
					return
				} else {
					if ok {
						params[permission] = true
					} else {
						params[permission] = false
					}
				}
			}

			result, err := exp.Evaluate(params)
			if err != nil {
				c.AbortWithStatus(consts.StatusInternalServerError)
				return
			}

			if res, ok := result.(bool); !ok {
				c.AbortWithStatus(consts.StatusInternalServerError)
				return
			} else {
				if !res {
					options.Forbidden(ctx, c)
					return
				}
			}

			c.Next(ctx)
			return
		}
		c.Next(ctx)
	}
}

// RequiresRoles tries to find the current subject and determine if the
// subject has the required roles according to predefined Casbin policies.
func (m *Middleware) RequiresRoles(expression string, opts ...Option) app.HandlerFunc {
	// Here we provide default options.
	options := NewOptions(opts...)
	return func(ctx context.Context, c *app.RequestContext) {
		if expression == "" {
			c.Next(ctx)
			return
		}
		// Look up current subject.
		sub := m.lookup(ctx, c)
		if sub == "" {
			options.Unauthorized(ctx, c)
			return
		}
		actualRoles, err := m.enforcer.GetRolesForUser(sub)
		if err != nil {
			c.AbortWithStatus(consts.StatusInternalServerError)
			return
		}

		if options.Logic == AND {
			// Must have all required roles.
			requiredRoles := strings.Split(expression, " ")
			for _, role := range requiredRoles {
				if !containsString(actualRoles, role) {
					options.Forbidden(ctx, c)
					return
				}
			}
			c.Next(ctx)
			return
		} else if options.Logic == OR {
			// Need to have at least one of required roles.
			requiredRoles := strings.Split(expression, " ")
			for _, role := range requiredRoles {
				if containsString(actualRoles, role) {
					c.Next(ctx)
					return
				}
			}
			options.Forbidden(ctx, c)
			return
		} else if options.Logic == CUSTOM {
			exp, err := govaluate.NewEvaluableExpression(expression)
			if err != nil {
				c.AbortWithStatus(consts.StatusInternalServerError)
				return
			}

			requiredRoles := exp.Vars()
			params := make(utils.H, len(requiredRoles))

			for _, requiredRole := range requiredRoles {
				params[requiredRole] = false
			}

			for _, actualRole := range actualRoles {
				params[actualRole] = true
			}

			result, err := exp.Evaluate(params)
			if err != nil {
				c.AbortWithStatus(consts.StatusInternalServerError)
				return
			}

			if res, ok := result.(bool); !ok {
				c.AbortWithStatus(consts.StatusInternalServerError)
				return
			} else {
				if !res {
					options.Forbidden(ctx, c)
					return
				}
			}

			c.Next(ctx)
			return
		}
		c.Next(ctx)
	}
}

func containsString(s []string, v string) bool {
	for _, vv := range s {
		if vv == v {
			return true
		}
	}
	return false
}

func stringSliceToInterfaceSlice(s []string) []interface{} {
	res := make([]interface{}, len(s))
	for i, v := range s {
		res[i] = v
	}
	return res
}
