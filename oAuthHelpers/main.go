package oAuthHelpers

import (
  "fmt"
  "strings"
  "net/http"
  "github.com/renra/go-errtrace/errtrace"
)

const (
  HeaderName = "Authorization"
  AccessTokenType = "Bearer"
  RefreshTokenType = "Basic"

  NoAuthHeaderFoundError = "No auth header found"
  WrongFormatError = "Wrong format of auth header"
)

type TokenWithType struct {
  Type string
  Token string
}

func readAuthHeader(headers http.Header) (*string, *errtrace.Error) {
  authorizationHeaders, found := headers[HeaderName]

  if found == false || len(authorizationHeaders) < 1 {
    return nil, errtrace.New(NoAuthHeaderFoundError)
  }

  return &authorizationHeaders[0], nil
}

func splitAuthHeader(headerValue string) (*TokenWithType, *errtrace.Error) {
  shards := strings.Split(headerValue, " ")

  if len(shards) != 2 {
    return nil, errtrace.New(WrongFormatError)
  }

  return &TokenWithType{ Type: shards[0], Token: shards[1] }, nil
}

func GetTokenWithTypeFromHeaders(headers http.Header) (*TokenWithType, *errtrace.Error) {
  authHeader, err := readAuthHeader(headers)

  if err != nil {
    return nil, err
  }

  tokenWithType, err := splitAuthHeader(*authHeader)

  if err != nil {
    return nil, err
  }

  return tokenWithType, nil
}

func WrongTokenTypeError(actualType string, wantedType string) string {
  return fmt.Sprintf(
    "Unsupported auth type: %s. I accept only %s",
    actualType,
    wantedType,
  )
}

func GetTokenFromHeaders(headers http.Header, wantedTokenType string) (*string, *errtrace.Error) {
  tokenWithType, err := GetTokenWithTypeFromHeaders(headers)

  if err != nil {
    return nil, err
  }

  if tokenWithType.Type != wantedTokenType {
    return nil, errtrace.New(WrongTokenTypeError(tokenWithType.Type, wantedTokenType))
  }

  return &tokenWithType.Token, nil
}

func GetAccessTokenFromHeaders(headers http.Header) (*string, *errtrace.Error) {
  return GetTokenFromHeaders(headers, AccessTokenType)
}

func GetRefreshTokenFromHeaders(headers http.Header) (*string, *errtrace.Error) {
  return GetTokenFromHeaders(headers, RefreshTokenType)
}
