package oAuthMiddleware

import (
  "fmt"
  "context"
  "net/http"
  "github.com/renra/go-oauth-helpers/oAuthHelpers"
)

func AddAccessTokenToContext(next http.HandlerFunc) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    token, err := oAuthHelpers.GetAccessTokenFromHeaders(r.Header)

    if err == nil {
      ctx := r.Context()

      r = r.WithContext(context.WithValue(ctx, "access_token", *token))

      next(w, r)
    } else {
      next(w, r)
    }
  }
}

func RequireAccessToken(next http.HandlerFunc) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    token, err := oAuthHelpers.GetAccessTokenFromHeaders(r.Header)

    if err == nil {
      ctx := r.Context()

      r = r.WithContext(context.WithValue(ctx, "access_token", *token))

      next(w, r)
    } else {
      w.WriteHeader(http.StatusUnauthorized)
      fmt.Fprintf(w, "")
    }
  }
}

func AddRefreshTokenToContext(next http.HandlerFunc) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    token, err := oAuthHelpers.GetRefreshTokenFromHeaders(r.Header)

    if err == nil {
      ctx := r.Context()

      r = r.WithContext(context.WithValue(ctx, "refresh_token", *token))

      next(w, r)
    } else {
      next(w, r)
    }
  }
}

func RequireRefreshToken(next http.HandlerFunc) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    token, err := oAuthHelpers.GetRefreshTokenFromHeaders(r.Header)

    if err == nil {
      ctx := r.Context()

      r = r.WithContext(context.WithValue(ctx, "refresh_token", *token))

      next(w, r)
    } else {
      w.WriteHeader(http.StatusUnauthorized)
      fmt.Fprintf(w, "")
    }
  }
}
