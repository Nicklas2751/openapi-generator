package org.openapitools.client.auth;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

class ApiKeyAuthTest {

    @Test
    void applyToParams_apiKeyNull_noChange() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));
        var copyOfRequestBuilder = requestBuilder.copy();
        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.QUERY, "key");
        apiKeyAuth.setApiKeyPrefix("somePrefix-");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build()).isEqualTo(copyOfRequestBuilder.build());
    }

    @Test
    void applyToParams_queryLocationNoQueryBefore_paramAddedToQuery() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));
        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.QUERY, "key");
        apiKeyAuth.setApiKeyPrefix("somePrefix");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().uri().getQuery()).isEqualTo("key=somePrefix apiKey");
    }

    @Test
    void applyToParams_queryLocationQueryBefore_paramAddedToExistingQuery() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login?q=abc&sort=asc"));
        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.QUERY, "key");
        apiKeyAuth.setApiKeyPrefix("somePrefix");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().uri().getQuery()).isEqualTo("q=abc&sort=asc&key=somePrefix apiKey");
    }

    @Test
    void applyToParams_queryLocationNoPrefixSet_paramAddedToQuery() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));
        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.QUERY, "key");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().uri().getQuery()).isEqualTo("key=apiKey");
    }

    @Test
    void applyToParams_headerLocationNoHeaders_paramAddedToHeader() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));
        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.HEADER, "key");
        apiKeyAuth.setApiKeyPrefix("somePrefix");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map()).containsExactly(entry("key", List.of("somePrefix apiKey")));
    }

    @Test
    void applyToParams_headerLocationExistingHeaders_paramAddedToHeaders() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));
        requestBuilder.header("Accept-Charset", "utf-8");

        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.HEADER, "key");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map()).containsExactly(
                entry("Accept-Charset", List.of("utf-8")),
                entry("key", List.of("apiKey"))
        );
    }

    @Test
    void applyToParams_cookieLocationNoCookies_paramAddedToCookies() {
        // given
        var uri = URI.create("http://localhost:8080/auth/login");
        var requestBuilder = HttpRequest.newBuilder(uri);

        var cookieManager = new CookieManager();
        var cookieStore = cookieManager.getCookieStore();
        var httpClient = HttpClient.newBuilder()
                .cookieHandler(cookieManager)
                .build();

        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.COOKIE, "key");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, httpClient);

        // then
        assertThat(cookieStore.getCookies()).containsExactly(
                new HttpCookie("key", "apiKey")
        );
    }

    @Test
    void applyToParams_cookieLocationExistingCookies_paramAddedToCookies() {
        // given
        var uri = URI.create("http://localhost:8080/auth/login");
        var requestBuilder = HttpRequest.newBuilder(uri);

        var cookieManager = new CookieManager();
        var cookieStore = cookieManager.getCookieStore();
        cookieStore.add(uri, new HttpCookie("testCookie", "testValue"));

        var httpClient = HttpClient.newBuilder()
                .cookieHandler(cookieManager)
                .build();

        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.COOKIE, "key");
        apiKeyAuth.setApiKey("apiKey");

        // when
        apiKeyAuth
                .applyToParams(requestBuilder, httpClient);

        // then
        assertThat(cookieStore.getCookies()).containsExactly(
                new HttpCookie("testCookie", "testValue"),
                new HttpCookie("key", "apiKey")
        );
    }

    @Test
    void applyToParams_cookieLocationNoCookieHandler_warningLogged() {
        // given
        var uri = URI.create("http://localhost:8080/auth/login");
        var requestBuilder = HttpRequest.newBuilder(uri);

        var httpClient = HttpClient.newBuilder()
                .build();

        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.COOKIE, "key");
        apiKeyAuth.setApiKey("apiKey");

        // when
        try(var logCaptor = LogCaptor.forClass(ApiKeyAuth.class)) {
            apiKeyAuth
                .applyToParams(requestBuilder, httpClient);
            // then
            assertThat(logCaptor.getLogs())
                .containsExactly("Can't add api key as cookie because no cookie handler is set!");
        }
    }

    @Test
    void applyToParams_cookieLocationCookieHandlerNotCookieManager_warningLogged() {
        // given
        var uri = URI.create("http://localhost:8080/auth/login");
        var requestBuilder = HttpRequest.newBuilder(uri);

        var httpClient = HttpClient.newBuilder()
                .cookieHandler(new CookieHandler(){
                    @Override
                    public Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) {
                        return Map.of();
                    }

                    @Override
                    public void put(URI uri, Map<String, List<String>> responseHeaders)  {

                    }
                })
                .build();

        var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.COOKIE, "key");
        apiKeyAuth.setApiKey("apiKey");

        // when
        try(var logCaptor = LogCaptor.forClass(ApiKeyAuth.class)) {
            apiKeyAuth
                .applyToParams(requestBuilder, httpClient);
            // then
            assertThat(logCaptor.getLogs())
                .containsExactly("Can't add api key as cookie because the cookie handler is no instance of cookie manager!");
        }
    }

}