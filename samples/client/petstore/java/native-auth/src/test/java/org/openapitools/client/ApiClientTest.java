package org.openapitools.client;

import com.github.scribejava.core.model.OAuth2AccessToken;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.openapitools.client.auth.*;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.SigningAlgorithm;

import java.math.BigInteger;
import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.security.spec.DSAParameterSpec;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ApiClientTest {
    public static final String BASE_URI = "http://localhost:8080/v1";
    public static final String OAUTH = "petstore_auth";
    public static final String BEARER_AUTH = "bearer_test";
    public static final String API_KEY = "api_key";
    public static final String API_KEY_QUERY = "api_key_query";
    public static final String HTTP_BASIC_AUTH = "http_basic_test";
    public static final String HTTP_SIGNATURE_AUTH = "http_signature_test";

    @Nested
    class constructorWithAuthMap {
        @Test
        void baseUriNull_usesDefaultBaseUri() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), null, Map.of());

            // then
            assertThat(client.getBaseUri()).isEqualTo("http://petstore.swagger.io:80/v2");
        }

        @Test
        void mapIsNull_petstoreOAuthSet() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, null);

            // then
            assertThat(client.getAuthentication(OAUTH))
                    .isInstanceOf(OAuth.class);
        }

        @Test
        void oauthSet_petstoreOAuthSet() {
            // given
            var oAuth = new OAuth("basePath", "token");

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(OAUTH, oAuth));

            // then
            assertThat(client.getAuthentication(OAUTH))
                    .isInstanceOf(OAuth.class)
                    .isSameAs(oAuth);
        }

        @Test
        void emptyMap_petstoreOAuthSet() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Collections.emptyMap());

            // then
            assertThat(client.getAuthentication(OAUTH))
                    .isInstanceOf(OAuth.class);
        }

        @Test
        void apiKeyAuthSet_apikeyApiKeyHeaderAuthSet() {
            // given
            var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.HEADER, API_KEY);

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(API_KEY, apiKeyAuth));

            // then
            assertThat(client.getAuthentication(API_KEY))
                    .isInstanceOf(ApiKeyAuth.class)
                    .isSameAs(apiKeyAuth);
        }

        @Test
        void emptyMap_apikeyApiKeyHeaderAuthSet() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Collections.emptyMap());

            // then
            assertThat(client.getAuthentication(API_KEY))
                    .isInstanceOf(ApiKeyAuth.class)
                    .extracting(a -> ((ApiKeyAuth) a).getLocation())
                    .isEqualTo(ApiKeyAuth.ApiKeyLocation.HEADER);
        }

        @Test
        void apiKeyAuthSet_apikeyqueryApiKeyQueryAuthSet() {
            // given
            var apiKeyAuth = new ApiKeyAuth(ApiKeyAuth.ApiKeyLocation.QUERY, API_KEY_QUERY);

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(API_KEY_QUERY, apiKeyAuth));

            // then
            assertThat(client.getAuthentication(API_KEY_QUERY))
                    .isInstanceOf(ApiKeyAuth.class)
                    .isSameAs(apiKeyAuth);
        }

        @Test
        void emptyMap_apikeyqueryApiKeyQueryAuthSet() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Collections.emptyMap());

            // then
            assertThat(client.getAuthentication(API_KEY_QUERY))
                    .isInstanceOf(ApiKeyAuth.class)
                    .extracting(a -> ((ApiKeyAuth) a).getLocation())
                    .isEqualTo(ApiKeyAuth.ApiKeyLocation.QUERY);
        }

        @Test
        void httpBasicAuthSet_httpbasictestHttpBasicAuthSet() {
            // given
            var basicAuth = new HttpBasicAuth();

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(HTTP_BASIC_AUTH, basicAuth));

            // then
            assertThat(client.getAuthentication(HTTP_BASIC_AUTH))
                    .isInstanceOf(HttpBasicAuth.class)
                    .isSameAs(basicAuth);
        }

        @Test
        void emptyMap_httpbasictestHttpBasicAuthSet() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Collections.emptyMap());

            // then
            assertThat(client.getAuthentication(HTTP_BASIC_AUTH))
                    .isInstanceOf(HttpBasicAuth.class);
        }

        @Test
        void httpBearerAuthSet_bearertestHttpBearerAuthSet() {
            // given
            var bearerAuth = new HttpBearerAuth("bearer");

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(BEARER_AUTH, bearerAuth));

            // then
            assertThat(client.getAuthentication(BEARER_AUTH))
                    .isInstanceOf(HttpBearerAuth.class)
                    .isSameAs(bearerAuth);
        }

        @Test
        void emptyMap_bearertestHttpBearerAuthSet() {
            // given

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Collections.emptyMap());

            // then
            assertThat(client.getAuthentication(BEARER_AUTH))
                    .isInstanceOf(HttpBearerAuth.class);
        }

        @Test
        void emptyMap_cookieManagerIsAddedToHttpClientBuilder() {
            // given
            var clientBuilder = HttpClient.newBuilder();
            clientBuilder.connectTimeout(Duration.ofSeconds(42));

            // when
            var client = new ApiClient(clientBuilder, ApiClient.createDefaultObjectMapper(), BASE_URI, Collections.emptyMap());

            // then
            assertThat(client.getHttpClient().cookieHandler())
                    .isPresent()
                    .get()
                    .isInstanceOf(CookieManager.class);

            //noinspection resource
            assertThat(clientBuilder.build().cookieHandler())
                    .isPresent()
                    .get()
                    .isInstanceOf(CookieManager.class);
        }

        @Test
        void httpSignatureAuthSet_httpsignaturetestHttpSignatureAuthSet() {
            // given
            var paramSpec = new DSAParameterSpec(
                    BigInteger.valueOf(1),
                    BigInteger.valueOf(2),
                    BigInteger.valueOf(5));

            var signatureAuth = new HttpSignatureAuth(
                    "key",
                    SigningAlgorithm.ECDSA_SHA256,
                    Algorithm.DSA_SHA1,
                    "parameterSpec",
                    paramSpec,
                    Collections.emptyList(),
                    3600L);

            // when
            var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(HTTP_SIGNATURE_AUTH, signatureAuth));

            // then
            assertThat(client.getAuthentication(HTTP_SIGNATURE_AUTH))
                    .isInstanceOf(HttpSignatureAuth.class)
                    .isSameAs(signatureAuth);
        }
    }

    @Test
    void setOauthBaseUri_oAuthSet_baseUriIsSetForOAuth() {
        // given
        var oAuth = new OAuth("http://localhost/", "v1/invalid");
        oAuth.setCredentials("clientId", "clientSecret", false);
        var client = new ApiClient(HttpClient.newBuilder(), ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(OAUTH, oAuth));

        // when
        client.setOauthBaseUri("http://petstore_auth/");

        // then
        assertThatThrownBy(() ->oAuth.obtainAccessToken("dgsd"))
                .hasMessageContaining(OAUTH);
    }

    @Test
    void getAuthentications_returnsAllAuthentications() {
        // given
        var client = new ApiClient();

        // when
        var authentications = client.getAuthentications();

        // then
        assertThat(authentications).containsOnlyKeys(OAUTH, API_KEY, API_KEY_QUERY, HTTP_BASIC_AUTH, BEARER_AUTH);
    }

    @Test
    void getAuthentications_authenticationsCantBeModified() {
        // given
        var client = new ApiClient();

        // when & then
        assertThatThrownBy(() -> client.getAuthentications().put("new_auth", new HttpBasicAuth()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void setUsername_setsUsernameForFirstBasicAuth() {
        // given
        var client = new ApiClient();
        var expectedUsername = "new_user";

        // when
        client.setUsername(expectedUsername);

        // then
        assertThat(((HttpBasicAuth)client.getAuthentication(HTTP_BASIC_AUTH)).getUsername()).isEqualTo(expectedUsername);
    }

    @Test
    void setPassword_setsUsernameForFirstBasicAuth() {
        // given
        var client = new ApiClient();
        var expectedPassword = "somethingSecret";

        // when
        client.setPassword(expectedPassword);

        // then
        assertThat(((HttpBasicAuth)client.getAuthentication(HTTP_BASIC_AUTH)).getPassword()).isEqualTo(expectedPassword);
    }

    @Test
    void setApiKey_setsApiKeyForFirstApiKeyAuth() {
        // given
        var client = new ApiClient();
        var expectedApiKey = "somethingSecret";

        // when
        client.setApiKey(expectedApiKey);

        // then
        assertThat(((ApiKeyAuth)client.getAuthentication(API_KEY)).getApiKey()).isEqualTo(expectedApiKey);
        assertThat(((ApiKeyAuth)client.getAuthentication(API_KEY_QUERY)).getApiKey()).isNull();
    }

    @Test
    void configureApiKeys_setsApiKeyForAllApiKeyAuth() {
        // given
        var client = new ApiClient();
        var expectedApiKey = "somethingSecret";
        var expectedApiKeyQuery = "somethingOtherSecret";

        // when
        client.configureApiKeys(Map.of(
                API_KEY, expectedApiKey,
                API_KEY_QUERY, expectedApiKeyQuery,
                "does_not_exist", "should_not_be_used"));

        // then
        assertThat(((ApiKeyAuth)client.getAuthentication(API_KEY)).getApiKey()).isEqualTo(expectedApiKey);
        assertThat(((ApiKeyAuth)client.getAuthentication(API_KEY_QUERY)).getApiKey()).isEqualTo(expectedApiKeyQuery);
    }

    @Test
    void setApiKeyPrefix_setsApiKeyPrefixForFirstApiKeyAuth() {
        // given
        var client = new ApiClient();
        var expectedPrefix = "Bearer";

        // when
        client.setApiKeyPrefix(expectedPrefix);

        // then
        assertThat(((ApiKeyAuth)client.getAuthentication(API_KEY)).getApiKeyPrefix()).isEqualTo(expectedPrefix);
    }

    @Test
    void setBearerToken_setsBearerTokenForFirstBearerAuth() {
        // given
        var client = new ApiClient();
        var expectedToken = "bearerTokenValue";

        // when
        client.setBearerToken(expectedToken);

        // then
        assertThat(((HttpBearerAuth)client.getAuthentication(BEARER_AUTH)).getBearerToken()).isEqualTo(expectedToken);
    }

    @Test
    void setAccessToken_setsAccessTokenForFirstOAuth() {
        // given
        var client = new ApiClient();
        var expectedToken = "accessTokenValue";

        // when
        client.setAccessToken(expectedToken);

        // then
        assertThat(((OAuth)client.getAuthentication(OAUTH)).getAccessToken()).isEqualTo(new OAuth2AccessToken(expectedToken));
    }

    @Nested
    class applySecurityAuthentication {
        @Test
        void appliesOAuth() throws ApiException {
            // given
            var oAuth = mock(OAuth.class);
            var httpClientBuilder = HttpClient.newBuilder();
            var client = new ApiClient(httpClientBuilder, ApiClient.createDefaultObjectMapper(), BASE_URI, Map.of(OAUTH, oAuth));

            var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/v1/pets"))
                    .POST(BodyPublishers.ofString("testBody"))
                    .header("Accept-Charset", "utf-8");

            // when
            client.applySecurityAuthentication(requestBuilder, List.of(OAUTH));

            // then
            verify(oAuth).applyToParams(requestBuilder, httpClientBuilder.build());
        }
    }

}