package oAuthHelpers

import (
  "context"
  "net/http"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

func AddToken(key string, tokenType string) Middleware {
  return func (next http.HandlerFunc) http.HandlerFunc {
    return func (w http.ResponseWriter, r *http.Request) {
      token, err := GetTokenFromHeaders(r.Header, tokenType)

      if err == nil {
        ctx := r.Context()
        r = r.WithContext(context.WithValue(ctx, key, *token))

        next(w, r)
      } else {
        next(w, r)
      }
    }
  }
}

func RequireToken(key string, tokenType string, errback http.HandlerFunc) Middleware {
  return func (next http.HandlerFunc) http.HandlerFunc {
    return func (w http.ResponseWriter, r *http.Request) {
      token, err := GetTokenFromHeaders(r.Header, tokenType)

      if err == nil {
        ctx := r.Context()
        r = r.WithContext(context.WithValue(ctx, key, *token))

        next(w, r)
      } else {
        errback(w, r)
      }
    }
  }
}

