package test

import (
  "testing"
  "github.com/stretchr/testify/suite"
)

func TestOAuthHelpers(t *testing.T) {
  suite.Run(t, new(OAuthHelpersSuite))
}

