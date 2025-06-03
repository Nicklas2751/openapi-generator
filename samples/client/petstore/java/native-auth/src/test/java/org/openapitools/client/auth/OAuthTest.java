package org.openapitools.client.auth;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.openapitools.client.ApiException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class OAuthTest {

    @Nested
    class ApplyToParams {
        @Test
        void noAccessToken_noHeaderSet() throws Exception {
            // given
            var oAuth = new OAuth("http://localhost/", "token");
            var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

            // when
            oAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

            // then
            assertThat(requestBuilder.build().headers().map()).isEmpty();
        }

        @Test
        void accessTokenSet_headerWithBearerToken() throws Exception {
            // given
            var oAuth = new OAuth("http://localhost/", "token");
            oAuth.setAccessToken("accessTokenValue");
            var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

            // when
            oAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

            // then
            assertThat(requestBuilder.build().headers().allValues("Authorization"))
                    .isEqualTo(List.of("Bearer accessTokenValue"));
        }

        @Test
        void existingHeaders_headerWithBearerAddedAdditionally() throws Exception {
            // given
            var oAuth = new OAuth("http://localhost/", "token");
            oAuth.setAccessToken(new OAuth2AccessToken("token123"));
            var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"))
                    .header("Accept", "application/json");

            // when
            oAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

            // then
            assertThat(requestBuilder.build().headers().map())
                    .containsEntry("Accept", List.of("application/json"))
                    .containsEntry("Authorization", List.of("Bearer token123"));
        }

        @Test
        void expiredAccessToken_renewsToken() throws Exception {
            // given
            var oAuth = spy(new OAuth("http://localhost/", "token"));
            var expiredToken = new OAuth2AccessToken("token123", null, -5, "refresh123", null, null);
            oAuth.setAccessToken(expiredToken);

            doReturn(new OAuth2AccessToken("newToken42"))
                    .when(oAuth).obtainAccessToken("refresh123");

            var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"))
                    .header("Accept", "application/json");

            // when
            oAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

            // then
            assertThat(requestBuilder.build().headers().map())
                    .containsEntry("Authorization", List.of("Bearer newToken42"));
        }
    }

    @Nested
    class ObtainAccessToken {
        private OAuth oAuth;
        private OAuth20Service service;

        @BeforeEach
        void setUp() {
            oAuth = new OAuth("http://localhost/", "token");
            service = Mockito.mock(OAuth20Service.class);
            // Service muss gesetzt werden, sonst gibt es ein Log und null-Return
            oAuth.setCredentials("clientId", "clientSecret", false);
            // Überschreibe das Service-Objekt mit dem Mock
            oAuth.setCredentials("clientId", "clientSecret", false);
            // Reflection, da das Feld private ist
            try {
                var field = OAuth.class.getDeclaredField("service");
                field.setAccessible(true);
                field.set(oAuth, service);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Test
        void applicationFlow_success() throws Exception {
            // given
            var token = new OAuth2AccessToken("appToken");
            when(service.getAccessTokenClientCredentialsGrant((String) null)).thenReturn(token);

            // when
            var result = oAuth.obtainAccessToken(null);

            // then
            assertThat(result.getAccessToken()).isEqualTo("appToken");
        }

        @Test
        void passwordFlow_success() throws Exception {
            // given
            oAuth.usePasswordFlow("user", "pw");
            var token = new OAuth2AccessToken("pwToken");
            when(service.getAccessTokenPasswordGrant("user", "pw", null)).thenReturn(token);

            // when
            var result = oAuth.obtainAccessToken(null);

            // then
            assertThat(result.getAccessToken()).isEqualTo("pwToken");
        }

        @Test
        void accessCodeFlow_success() throws Exception {
            // given
            oAuth.useAuthorizationCodeFlow("theCode");
            var token = new OAuth2AccessToken("codeToken");
            when(service.getAccessToken("theCode")).thenReturn(token);

            // when
            var result = oAuth.obtainAccessToken(null);

            // then
            assertThat(result.getAccessToken()).isEqualTo("codeToken");
        }

        @Test
        void refreshToken_success() throws Exception {
            // given
            var token = new OAuth2AccessToken("refreshToken");
            when(service.refreshAccessToken("refresh123")).thenReturn(token);

            // when
            var result = oAuth.obtainAccessToken("refresh123");

            // then
            assertThat(result.getAccessToken()).isEqualTo("refreshToken");
        }

        @Test
        void serviceNull_returnsNull() throws Exception {
            // given
            // Service auf null setzen
            try {
                var field = OAuth.class.getDeclaredField("service");
                field.setAccessible(true);
                field.set(oAuth, null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            // when
            var result = oAuth.obtainAccessToken(null);

            // then
            assertThat(result).isNull();
        }

        @Test
        void refreshToken_throwsApiException() throws Exception {
            // given
            when(service.refreshAccessToken("fail"))
                    .thenThrow(new ExecutionException(new RuntimeException("fail")));

            // when/then
            assertThatThrownBy(() -> oAuth.obtainAccessToken("fail"))
                    .isInstanceOf(ApiException.class)
                    .hasMessageContaining("Refreshing the access token");
        }

        @Test
        void applicationFlow_throwsApiException() throws Exception {
            // given
            when(service.getAccessTokenClientCredentialsGrant((String) null))
                    .thenThrow(new ExecutionException(new RuntimeException("fail")));

            // when/then
            assertThatThrownBy(() -> oAuth.obtainAccessToken(null))
                    .isInstanceOf(ApiException.class);
        }
    }
}