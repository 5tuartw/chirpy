package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	secret := "super_secret_key"
	userID := uuid.New()
	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	validatedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if validatedID != userID {
		t.Errorf("expected userID %v, got %v", userID, validatedID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	secret := "super_secret_key"
	userID := uuid.New()

	expiredToken, err := MakeJWT(userID, secret, -1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	_, err = ValidateJWT(expiredToken, secret)

	if err == nil || !strings.Contains(err.Error(), "token is expired") {
		t.Errorf("expected token expiration error, got: %v", err)
	}
}

func TestValidateJWT_WrongToken(t *testing.T) {
	secret := "super_secret_key"
	userID := uuid.New()
	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	wrongSecret := "wrong_key"
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Errorf("expected invalid key error")
	}

}

func TestGetBearerToken(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name           string
		headerValue    string
		expectedToken  string
		expectError    bool
		errorSubstring string
	}{
		{
			name:          "Valid Authorization Header",
			headerValue:   "Bearer abc123token",
			expectedToken: "abc123token",
			expectError:   false,
		},
		{
			name:          "Valid Authorization Header with Mixed Case",
			headerValue:   "beARer abc123token",
			expectedToken: "abc123token",
			expectError:   false,
		},
		{
			name:           "Missing Authorization Header",
			headerValue:    "",
			expectedToken:  "",
			expectError:    true,
			errorSubstring: "no authorization header",
		},
		{
			name:           "Invalid Format - No Bearer",
			headerValue:    "abc123token",
			expectedToken:  "",
			expectError:    true,
			errorSubstring: "authorization header format",
		},
		{
			name:           "Invalid Format - No Token",
			headerValue:    "Bearer ",
			expectedToken:  "",
			expectError:    true,
			errorSubstring: "authorization header format",
		},
		{
			name:           "Invalid Format - Extra Parts",
			headerValue:    "Bearer token extra",
			expectedToken:  "",
			expectError:    true,
			errorSubstring: "authorization header format",
		},
	}

	// Run tests
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test headers
			headers := http.Header{}
			if tc.headerValue != "" {
				headers.Add("Authorization", tc.headerValue)
			}

			// Call function
			token, err := GetBearerToken(headers)

			// Check error
			if tc.expectError {
				if err == nil {
					t.Fatalf("Test '%s': Expected error but got nil", tc.name)
				}
				if tc.errorSubstring != "" && !strings.Contains(err.Error(), tc.errorSubstring) {
					t.Fatalf("Test '%s': Expected error to contain %q but got %q",
						tc.name, tc.errorSubstring, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Test '%s': Expected no error but got: %v", tc.name, err)
				}
			}

			// Check token
			if token != tc.expectedToken {
				t.Fatalf("Test '%s': Expected token %q but got %q",
					tc.name, tc.expectedToken, token)
			}
		})
	}
}
