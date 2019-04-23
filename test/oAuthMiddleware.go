package test

import (
  "fmt"
  "net/http"
  "net/http/httptest"
  "app/oAuthHelpers"
  "app/oAuthMiddleware"
  "github.com/stretchr/testify/suite"
  "github.com/stretchr/testify/assert"
)

type TestHttpHandler struct {
}

func (handler *TestHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  switch r.URL.Path {
  case "/you_can_send_me_access_token":
    oAuthMiddleware.AddAccessTokenToContext(func (writer http.ResponseWriter, req *http.Request) {
      maybeToken := req.Context().Value("access_token")
      token, _ := maybeToken.(string)

      fmt.Fprintf(writer, "%s", token)
    })(w, r)
  case "/you_must_send_me_access_token":
    oAuthMiddleware.RequireAccessToken(func (writer http.ResponseWriter, req *http.Request) {
      maybeToken := req.Context().Value("access_token")
      token, _ := maybeToken.(string)

      fmt.Fprintf(writer, "%s", token)
    })(w, r)
  case "/you_can_send_me_refresh_token":
    oAuthMiddleware.AddRefreshTokenToContext(func (writer http.ResponseWriter, req *http.Request) {
      maybeToken := req.Context().Value("refresh_token")
      token, _ := maybeToken.(string)

      fmt.Fprintf(writer, "%s", token)
    })(w, r)
  case "/you_must_send_me_refresh_token":
    oAuthMiddleware.RequireRefreshToken(func (writer http.ResponseWriter, req *http.Request) {
      maybeToken := req.Context().Value("refresh_token")
      token, _ := maybeToken.(string)

      fmt.Fprintf(writer, "%s", token)
    })(w, r)
  }
}

type OAuthMiddlewareSuite struct {
  suite.Suite
  handler *TestHttpHandler
}

func (suite *OAuthMiddlewareSuite) SetupSuite() {
  suite.handler = &TestHttpHandler{}
}

func (suite *OAuthMiddlewareSuite) TestAddAccessTokenToContext() {
  tokenType := oAuthHelpers.AccessTokenType
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_can_send_me_access_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), tokenValue, recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddAccessTokenToContext_NoHeaderSent() {
  request, _ := http.NewRequest("GET", "/you_can_send_me_access_token", nil)
  recorder := httptest.NewRecorder()

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddAccessTokenToContext_WrongFormat() {
  request, _ := http.NewRequest("GET", "/you_can_send_me_access_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, "foo")

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddAccessTokenToContext_WrongTokenType() {
  tokenType := "SomeCustomTokeType"
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_can_send_me_access_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireAccessToken() {
  tokenType := oAuthHelpers.AccessTokenType
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_must_send_me_access_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), tokenValue, recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireAccessToken_NoHeaderSent() {
  request, _ := http.NewRequest("GET", "/you_must_send_me_access_token", nil)
  recorder := httptest.NewRecorder()

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusUnauthorized, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireAccessToken_WrongFormat() {
  request, _ := http.NewRequest("GET", "/you_must_send_me_access_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, "foo")

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusUnauthorized, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireAccessToken_WrongTokenType() {
  tokenType := "SomeCustomTokeType"
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_must_send_me_access_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusUnauthorized, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddRefreshTokenToContext() {
  tokenType := oAuthHelpers.RefreshTokenType
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_can_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), tokenValue, recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddRefreshTokenToContext_NoHeaderSent() {
  request, _ := http.NewRequest("GET", "/you_can_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddRefreshTokenToContext_WrongFormat() {
  request, _ := http.NewRequest("GET", "/you_can_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, "foo")

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestAddRefreshTokenToContext_WrongTokenType() {
  tokenType := "SomeCustomTokeType"
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_can_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireRefreshToken() {
  tokenType := oAuthHelpers.RefreshTokenType
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_must_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusOK, recorder.Code)
  assert.Equal(suite.T(), tokenValue, recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireRefreshToken_NoHeaderSent() {
  request, _ := http.NewRequest("GET", "/you_must_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusUnauthorized, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireRefreshToken_WrongFormat() {
  request, _ := http.NewRequest("GET", "/you_must_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, "foo")

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusUnauthorized, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}

func (suite *OAuthMiddlewareSuite) TestRequireRefreshToken_WrongTokenType() {
  tokenType := "SomeCustomTokeType"
  tokenValue := "123"

  request, _ := http.NewRequest("GET", "/you_must_send_me_refresh_token", nil)
  recorder := httptest.NewRecorder()
  request.Header.Add(oAuthHelpers.HeaderName, fmt.Sprintf("%s %s", tokenType, tokenValue))

  suite.handler.ServeHTTP(recorder, request)

  assert.Equal(suite.T(), http.StatusUnauthorized, recorder.Code)
  assert.Equal(suite.T(), "", recorder.Body.String())
}
