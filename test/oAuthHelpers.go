package test

import (
  "fmt"
  "net/http"
  "app/oAuthHelpers"
  "github.com/stretchr/testify/suite"
  "github.com/stretchr/testify/assert"
)

type OAuthHelpersSuite struct {
  suite.Suite
}

/// GetTokenWithTypeFromHeaders ///

func (suite *OAuthHelpersSuite) TestGetTokenWithTypeFromHeaders() {
  tokenType := "Whatever"
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", tokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  tokenWithType, err := oAuthHelpers.GetTokenWithTypeFromHeaders(headers)

  assert.Nil(suite.T(), err)
  assert.NotNil(suite.T(), tokenWithType)
  assert.Equal(suite.T(), tokenType, tokenWithType.Type)
  assert.Equal(suite.T(), tokenValue, tokenWithType.Token)
}

func (suite *OAuthHelpersSuite) TestGetTokenWithTypeFromHeaders_HeaderWithInvalidFormat() {
  headers := http.Header{
    oAuthHelpers.HeaderName: []string{"foo"},
  }

  tokenWithType, err := oAuthHelpers.GetTokenWithTypeFromHeaders(headers)

  assert.Nil(suite.T(), tokenWithType)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongFormatError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetTokenWithTypeFromHeaders_NoHeaderFound() {
  headers := http.Header{}

  tokenWithType, err := oAuthHelpers.GetTokenWithTypeFromHeaders(headers)

  assert.Nil(suite.T(), tokenWithType)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.NoAuthHeaderFoundError, err.Error())
}

/// GetTokenFromHeaders ///

func (suite *OAuthHelpersSuite) TestGetTokenFromHeaders() {
  tokenType := "whateverYouWant"
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", tokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  token, err := oAuthHelpers.GetTokenFromHeaders(headers, tokenType)

  assert.Nil(suite.T(), err)
  assert.NotNil(suite.T(), token)
  assert.Equal(suite.T(), tokenValue, *token)
}

func (suite *OAuthHelpersSuite) TestGetTokenFromHeaders_HeaderWithInvalidFormat() {
  tokenType := "whateverYouWant"
  headers := http.Header{
    oAuthHelpers.HeaderName: []string{"foo"},
  }

  token, err := oAuthHelpers.GetTokenFromHeaders(headers, tokenType)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongFormatError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetTokenFromHeaders_NoHeaderFound() {
  tokenType := "whateverYouWant"
  headers := http.Header{}

  token, err := oAuthHelpers.GetTokenFromHeaders(headers, tokenType)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.NoAuthHeaderFoundError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetTokenFromHeaders_WrongTokenType() {
  tokenType := "whateverYouWant"
  actualTokenType := "somethingYouDoNotWant"
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", actualTokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  token, err := oAuthHelpers.GetTokenFromHeaders(headers, tokenType)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongTokenTypeError(actualTokenType, tokenType), err.Error())
}

/// GetAccessTokenFromHeaders ///

func (suite *OAuthHelpersSuite) TestGetAccessTokenFromHeaders() {
  tokenType := oAuthHelpers.AccessTokenType
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", tokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  token, err := oAuthHelpers.GetAccessTokenFromHeaders(headers)

  assert.Nil(suite.T(), err)
  assert.NotNil(suite.T(), token)
  assert.Equal(suite.T(), tokenValue, *token)
}

func (suite *OAuthHelpersSuite) TestGetAccessTokenFromHeaders_HeaderWithInvalidFormat() {
  headers := http.Header{
    oAuthHelpers.HeaderName: []string{"foo"},
  }

  token, err := oAuthHelpers.GetAccessTokenFromHeaders(headers)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongFormatError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetAccessTokenFromHeaders_NoHeaderFound() {
  headers := http.Header{}

  token, err := oAuthHelpers.GetAccessTokenFromHeaders(headers)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.NoAuthHeaderFoundError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetAccessTokenFromHeaders_WrongTokenType() {
  actualTokenType := "somethingYouDoNotWant"
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", actualTokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  token, err := oAuthHelpers.GetAccessTokenFromHeaders(headers)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongTokenTypeError(actualTokenType, oAuthHelpers.AccessTokenType), err.Error())
}

/// GetRefreshTokenFromHeaders ///

func (suite *OAuthHelpersSuite) TestGetRefreshTokenFromHeaders() {
  tokenType := oAuthHelpers.RefreshTokenType
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", tokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  token, err := oAuthHelpers.GetRefreshTokenFromHeaders(headers)

  assert.Nil(suite.T(), err)
  assert.NotNil(suite.T(), token)
  assert.Equal(suite.T(), tokenValue, *token)
}

func (suite *OAuthHelpersSuite) TestGetRefreshTokenFromHeaders_HeaderWithInvalidFormat() {
  headers := http.Header{
    oAuthHelpers.HeaderName: []string{"foo"},
  }

  token, err := oAuthHelpers.GetRefreshTokenFromHeaders(headers)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongFormatError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetRefreshTokenFromHeaders_NoHeaderFound() {
  headers := http.Header{}

  token, err := oAuthHelpers.GetRefreshTokenFromHeaders(headers)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.NoAuthHeaderFoundError, err.Error())
}

func (suite *OAuthHelpersSuite) TestGetRefreshTokenFromHeaders_WrongTokenType() {
  actualTokenType := "somethingYouDoNotWant"
  tokenValue := "SomeValue"
  headerValue := fmt.Sprintf("%s %s", actualTokenType, tokenValue)

  headers := http.Header{
    oAuthHelpers.HeaderName: []string{headerValue},
  }

  token, err := oAuthHelpers.GetRefreshTokenFromHeaders(headers)

  assert.Nil(suite.T(), token)
  assert.NotNil(suite.T(), err)
  assert.Equal(suite.T(), oAuthHelpers.WrongTokenTypeError(actualTokenType, oAuthHelpers.RefreshTokenType), err.Error())
}
