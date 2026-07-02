package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("No Authorization Header", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)

		assert.ErrorIs(t, err, ErrNoAuthHeaderIncluded)
		assert.Empty(t, apiKey)
	})

	t.Run("Malformed Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer abc123")

		apiKey, err := GetAPIKey(headers)

		assert.Error(t, err)
		assert.Equal(t, "malformed authorization header", err.Error())
		assert.Empty(t, apiKey)
	})

	t.Run("Valid Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey abc123")

		apiKey, err := GetAPIKey(headers)

		assert.NoError(t, err)
		assert.Equal(t, "abc123", apiKey)
	})
}

