package oAuthHelpers

import (
  "fmt"
  "net/http"
)

func AddAccessTokenHeader(req *http.Request, token string) {
  AddTokenHeader(req, AccessTokenType, token)
}

func AddRefreshTokenHeader(req *http.Request, token string) {
  AddTokenHeader(req, RefreshTokenType, token)
}

func AddTokenHeader(req *http.Request, tokenType string, token string) {
  req.Header.Add(HeaderName, fmt.Sprintf("%s %s", tokenType, token))
}
