# Casbin (This is a community driven project)

Casbin is an authorization library that supports access control models like ACL, RBAC, ABAC.

This repo inspired by [fiber-casbin](https://github.com/gofiber/contrib/tree/main/casbin) and adapted to Hertz.

## Install

``` shell
go get github.com/hertz-contrib/casbin
```

## Import

```go
import "github.com/hertz-contrib/casbin"
```

## Example

```go
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

    h.GET("/book/r", auth.RequiresPermissions("book:read", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you read the book successfully")
    })
    h.GET("/book/rw", auth.RequiresPermissions("book:read book:write", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you read the book failed")
    })
    h.GET("/book/custom/rw", auth.RequiresPermissions("book:read && book:write", casbin.WithLogic(casbin.CUSTOM)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you read the book failed")
    })
    
    h.POST("/book/u", auth.RequiresRoles("user", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you posted a book successfully")
    })
    h.POST("/book/ua", auth.RequiresRoles("user admin", casbin.WithLogic(casbin.AND)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you posted a book failed")
    })
    h.POST("/book/custom/ua", auth.RequiresRoles("user && admin", casbin.WithLogic(casbin.CUSTOM)), func(ctx context.Context, c *app.RequestContext) {
        c.String(200, "you posted a book failed")
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
```

## Options

| Option                    | Default                                                      | Description                                                  |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Logic                     | AND                                                          | Logic is the logical operation (AND/OR/CUSTOM) used in permission checks in case multiple permissions or roles are specified. |
| PermissionParser          | PermissionParserWithSeparator(":")                           | PermissionParserFunc is used for parsing the permission to extract object and action usually. |
| PermissionParserSeparator | *                                                            | PermissionParserSeparator is used for parsing the permission to extract object and action usually. |
| Unauthorized              | func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(consts.StatusUnauthorized) }  | Unauthorized defines the response body for unauthorized responses. |
| Forbidden                 | func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(consts.StatusForbidden) } | Forbidden defines the response body for forbidden responses. |

**Attention**: when use `CUSTOM` in `WithLogic`, use `WithPermissionParser` Option is forbidden.
