package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKeys(t *testing.T){
	tests := map[string]struct{
		headers			http.Header
		expectedKey		string
		expectedError	error	
	}{
		"NoAuthHeader" : {headers: http.Header{}, expectedKey: "", expectedError: auth.ErrNoAuthHeaderIncluded},
		"MalformedAuth-NoAPIKeyPrefix": {headers: http.Header{"Authorization": []string{"123Bakr"}}, expectedKey: "1", expectedError: auth.ErrMalformedToken},
		"MalformedAuth-MissingToken": {headers: http.Header{"Authorization": []string{"ApiKey"}}, expectedKey: "", expectedError: auth.ErrMalformedToken},
		"ValidKey": {headers: http.Header{"Authorization": []string{"ApiKey bakr123"}}, expectedKey: "bakr123", expectedError: nil},
	}

	for name, tc := range tests{
		t.Run(name, func(t *testing.T) {
			key, err := auth.GetAPIKey(tc.headers)
			if key != tc.expectedKey{
				t.Errorf("expected API key:%v, got:%v", tc.expectedKey, key)
			}
			if  (err == nil && tc.expectedError != nil) || (err != nil && !errors.Is(err, tc.expectedError)){
				t.Errorf("expected error:%v, got:%v", tc.expectedError, err)
			}
		})
	}
}