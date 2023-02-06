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

package main

import (
	"context"
	"log"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/hertz-contrib/casbin"
	"github.com/hertz-contrib/sessions"
	"github.com/hertz-contrib/sessions/cookie"
)

func main() {
	h := server.Default()

	// Using sessions and casbin.
	store := cookie.NewStore([]byte("secret"))
	h.Use(sessions.New("session", store))
	auth, err := casbin.NewCasbinMiddleware("example/config/model.conf", "example/config/policy.csv", subjectFromSession)
	if err != nil {
		log.Fatal(err)
	}

	h.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		// Verify username and password.
		// ...

		// Store current subject in session
		session := sessions.Default(c)
		session.Set("name", "alice")
		err := session.Save()
		if err != nil {
			log.Fatal(err)
		}
		c.String(200, "you login successfully")
	})

	h.GET("/book", auth.RequiresPermissions([]string{"book:read"}, casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
		c.String(200, "you read the book successfully")
	})
	h.POST("/book", auth.RequiresRoles([]string{"user"}, casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
		c.String(200, "you posted a book successfully")
	})

	h.Spin()
}

// subjectFromSession get subject from session.
func subjectFromSession(ctx context.Context, c *app.RequestContext) string {
	// Get subject from session.
	session := sessions.Default(c)
	if subject, ok := session.Get("name").(string); !ok {
		return ""
	} else {
		return subject
	}
}
