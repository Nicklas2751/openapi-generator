package org.openapitools.client.auth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

class HttpBearerAuthTest {

    @Test
    void applyToParams_noToken_noHeaderSet() {
        // given
        var bearerAuth = new HttpBearerAuth("bearer");
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

        // when
        bearerAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map()).isEmpty();
    }

    @Test
    void applyToParams_tokenSet_headerWithBearerToken() {
        // given
        var bearerAuth = new HttpBearerAuth("bearer");
        bearerAuth.setBearerToken("myToken");
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

        // when
        bearerAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().allValues("Authorization"))
                .isEqualTo(List.of("Bearer myToken"));
    }

    @Test
    void applyToParams_tokenSetWithDifferentScheme_headerWithCorrectScheme() {
        // given
        var bearerAuth = new HttpBearerAuth("JWT");
        bearerAuth.setBearerToken("jwtToken");
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

        // when
        bearerAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().allValues("Authorization"))
                .isEqualTo(List.of("JWT jwtToken"));
    }

    @Test
    void applyToParams_existingHeaders_headerWithBearerAddedAdditionally() {
        // given
        var bearerAuth = new HttpBearerAuth("bearer");
        bearerAuth.setBearerToken("token123");
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"))
                .header("Accept", "application/json");

        // when
        bearerAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map())
                .containsExactly(
                        entry("Accept", List.of("application/json")),
                        entry("Authorization", List.of("Bearer token123"))
                );
    }

    @Test
    void applyToParams_schemeNull_headerWithTokenOnly() {
        // given
        var bearerAuth = new HttpBearerAuth(null);
        bearerAuth.setBearerToken("tokenOnly");
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

        // when
        bearerAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().allValues("Authorization"))
                .isEqualTo(List.of("tokenOnly"));
    }
}