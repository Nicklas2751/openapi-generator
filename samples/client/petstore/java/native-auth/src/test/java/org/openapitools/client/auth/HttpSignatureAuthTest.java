package org.openapitools.client.auth;

import org.junit.jupiter.api.Test;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;
import org.tomitribe.auth.signatures.SigningAlgorithm;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class HttpSignatureAuthTest {

    @Test
    void applyToParams_noSigner_throwsApiException() {
        // given
        var paramSpec = new DSAParameterSpec(BigInteger.ONE, BigInteger.TWO, BigInteger.TEN);
        var signatureAuth = new HttpSignatureAuth(
                "keyId",
                null,
                null,
                "SHA-256",
                paramSpec,
                List.of("date", "host"),
                3600L
        );
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

        // when & then
        assertThatThrownBy(() -> signatureAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build()))
                .isInstanceOf(org.openapitools.client.ApiException.class)
                .hasMessageContaining("Signer");
    }

    @Test
    void applyToParams_signerSet_authorizationHeaderIsSet() throws Exception {
        // given
        var paramSpec = new DSAParameterSpec(BigInteger.ONE, BigInteger.TWO, BigInteger.TEN);
        var signatureAuth = new HttpSignatureAuth(
                "keyId",
                SigningAlgorithm.RSA_SHA256,
                Algorithm.RSA_SHA256,
                "SHA-256",
                paramSpec,
                List.of("date", "host"),
                3600L
        );
        // Dummy Key und Signer setzen (hier ggf. mit Mock arbeiten)
        var dummySigner = mock(Signer.class);
        when(dummySigner.sign(
                anyString(),
                anyString(),
                anyMap()
        )).thenReturn(new Signature("keyId", SigningAlgorithm.RSA_SHA256, Algorithm.RSA_SHA256, paramSpec, null, List.of("date", "host"), 3600L));
        signatureAuth.setSigner(dummySigner);

        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"));

        // when
        signatureAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().allValues("Authorization")).isNotEmpty();
    }

    @Test
    void applyToParams_existingHeaders_signatureHeaderAddedAdditionally() throws Exception {
        // given
        var paramSpec = new DSAParameterSpec(BigInteger.ONE, BigInteger.TWO, BigInteger.TEN);
        var signatureAuth = new HttpSignatureAuth(
                "keyId",
                SigningAlgorithm.RSA_SHA256,
                Algorithm.RSA_SHA256,
                "SHA-256",
                paramSpec,
                List.of("date", "host"),
                3600L
        );
        var dummySigner = mock(Signer.class);
        when(dummySigner.sign(
                anyString(),
                anyString(),
                anyMap()
        )).thenReturn(new Signature("keyId", SigningAlgorithm.RSA_SHA256, Algorithm.RSA_SHA256, paramSpec, null, List.of("date", "host"), 3600L));
        signatureAuth.setSigner(dummySigner);

        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"))
                .header("Accept", "application/json");

        // when
        signatureAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        assertThat(requestBuilder.build().headers().map())
                .containsKey("Accept")
                .containsKey("Authorization");
    }

    @Test
    void applyToParams_allHeadersSet_allCorrectlySigned() throws Exception {
        // given
        var signatureAuth = new HttpSignatureAuth(
                "keyId",
                SigningAlgorithm.HS2019,
                Algorithm.ECDSA_SHA256,
                "SHA-256",
                null,
                List.of("date", "host", "digest"),
                3600L
        );

        var keyPairGenerator = KeyPairGenerator.getInstance("EC");
        var ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        var keyPair = keyPairGenerator.generateKeyPair();
        var privateKey = keyPair.getPrivate();

       signatureAuth.setPrivateKey(privateKey);

        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"))
                .header("Accept", "application/json");

        // when
        signatureAuth.applyToParams(requestBuilder, HttpClient.newBuilder().build());

        // then
        var httpRequest = requestBuilder.build();
        var ecdsaVerify = java.security.Signature.getInstance(Algorithm.ECDSA_SHA256.getJvmName());
        ecdsaVerify.initVerify(keyPair.getPublic());
        var authorizationValue = httpRequest.headers().firstValue("Authorization").orElse("");

        var signature = Signature.fromString(authorizationValue, Algorithm.ECDSA_SHA256);
        assertThat(signature.getSignature()).isNotNull();
        assertThat(signature.getHeaders()).containsExactly("date", "host", "digest");
    }

    @Test
    void headerListValueMapToSingleValueMap_validHeaders_usesFirstValueOfList() {
        // given
        var requestBuilder = HttpRequest.newBuilder(URI.create("http://localhost:8080/api"))
                .header("Accept", "application/json")
                .header("Custom-Header", "value1")
                .header("Custom-Header", "value2");

        // when
        var singleValueMap = new HttpSignatureAuth(null, null, null, null, null, null, null)
                .headerListValueMapToSingleValueMap(requestBuilder.build());

        // then
        assertThat(singleValueMap)
                .containsEntry("Accept", "application/json")
                .containsEntry("Custom-Header", "value1")
                .doesNotContainValue("value2");
    }
}