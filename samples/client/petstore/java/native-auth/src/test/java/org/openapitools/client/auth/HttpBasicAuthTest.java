package org.openapitools.client.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

class HttpBasicAuthTest {
    private static Stream<Arguments> applyToParamsArgumentSource() {
        return Stream.of(
            Arguments.of("", "", "Og=="),
            Arguments.of("username",    null, "dXNlcm5hbWU6"),
            Arguments.of(null,  "password",    "OnBhc3N3b3Jk"),
            Arguments.of("username", "password", "dXNlcm5hbWU6cGFzc3dvcmQ="),
            Arguments.of("uß%rn(m\"", "p4s?wör_d", "dcOfJXJuKG0iOnA0cz93w7ZyX2Q=")
        );
    }

    @Test
    void applyToParams_usernameAndPasswordNull_noHeaderSet() {
        // given
        var basicAuth = new HttpBasicAuth();
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));

        // when
        basicAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map()).isEmpty();
    }

    @Test
    void applyToParams_existingHeaders_headerWithCBasicAuthAddedAdditionally() {
        // given
        var basicAuth = new HttpBasicAuth();
        basicAuth.setUsername("username");
        basicAuth.setPassword("password");

        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"))
                .header("Accept-Charset", "utf-8");

        // when
        basicAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map())
                .containsExactly(
                        entry("Accept-Charset",List.of("utf-8")),
                        entry("Authorization",List.of("Basic dXNlcm5hbWU6cGFzc3dvcmQ="))
                );
    }

    @ParameterizedTest
    @MethodSource("applyToParamsArgumentSource")
    void applyToParams_validUsernamePassword_headerWithCorrectEncodedBasicAuth(String username, String password, String encodedUsernamePassword) {
        // given
        var basicAuth = new HttpBasicAuth();
        basicAuth.setUsername(username);
        basicAuth.setPassword(password);

        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/auth/login"));

        // when
        basicAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().allValues("Authorization"))
                .isEqualTo(List.of("Basic " + encodedUsernamePassword));
    }

}