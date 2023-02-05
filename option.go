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
	"errors"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

// LookupHandler is used to look up current subject in runtime.
// If it can not find anything, just return an empty string.
type LookupHandler func(ctx context.Context, c *app.RequestContext) string

// Logic is the logical operation (AND/OR) used in permission checks
// in case multiple permissions or roles are specified.
type Logic int

// PermissionParserFunc is used for parsing the permission
// to extract object and action usually
type PermissionParserFunc func(str string) []string

const (
	AND Logic = iota
	OR
)

var errLookupNil = errors.New("[Casbin] Lookup is nil")

// Option is the only struct that can be used to set Options.
type Option struct {
	F func(o *Options)
}

type Options struct {
	// Logic is the logical operation (AND/OR) used in permission checks
	// in case multiple permissions or roles are specified.
	// Optional. Default: AND
	Logic Logic

	// PermissionParserFunc is used for parsing the permission
	// to extract object and action usually
	// Optional. Default: PermissionParserWithSeparator(":")
	PermissionParser PermissionParserFunc

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(ctx context.Context, c *app.RequestContext) {
	//		c.AbortWithStatus(http.StatusUnauthorized)
	//	},
	Unauthorized app.HandlerFunc

	// Forbidden defines the response body for forbidden responses.
	// Optional. Default: func(ctx context.Context, c *app.RequestContext) {
	//		c.AbortWithStatus(http.StatusForbidden)
	//	},
	Forbidden app.HandlerFunc
}

// Apply to apply options.
func (o *Options) Apply(opts []Option) {
	for _, op := range opts {
		op.F(o)
	}
}

var OptionsDefault = Options{
	Logic:            AND,
	PermissionParser: PermissionParserWithSeparator(":"),
	Unauthorized: func(ctx context.Context, c *app.RequestContext) {
		c.AbortWithStatus(http.StatusUnauthorized)
	},
	Forbidden: func(ctx context.Context, c *app.RequestContext) {
		c.AbortWithStatus(http.StatusForbidden)
	},
}

func NewOptions(opts ...Option) *Options {
	options := &Options{
		Logic:            OptionsDefault.Logic,
		PermissionParser: OptionsDefault.PermissionParser,
		Unauthorized:     OptionsDefault.Unauthorized,
		Forbidden:        OptionsDefault.Forbidden,
	}
	options.Apply(opts)
	return options
}

// WithLogic sets the logical operator used in permission or role checks.
func WithLogic(logic Logic) Option {
	return Option{
		F: func(o *Options) {
			o.Logic = logic
		},
	}
}

func WithPermissionParser(pp PermissionParserFunc) Option {
	return Option{
		F: func(o *Options) {
			o.PermissionParser = pp
		},
	}
}

func WithUnauthorized(u app.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.Unauthorized = u
		},
	}
}

func WithForbidden(f app.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.Forbidden = f
		},
	}
}

func PermissionParserWithSeparator(sep string) PermissionParserFunc {
	return func(str string) []string {
		return strings.Split(str, sep)
	}
}
