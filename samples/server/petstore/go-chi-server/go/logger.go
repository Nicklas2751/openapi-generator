// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

/*
 * OpenAPI Petstore
 *
 * This is a sample server Petstore server. For this sample, you can use the api key `special-key` to test the authorization filters.
 *
 * API version: 1.0.0
 */

package petstoreserver

import (
	"net/http"
	"github.com/go-chi/chi/v5/middleware"
)

func Logger(inner http.Handler) http.Handler {
	return middleware.Logger(inner)
}
