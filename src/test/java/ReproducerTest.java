import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import java.io.IOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ReproducerTest {

  @RegisterExtension
  WireMockExtension serverMock = WireMockExtension.newInstance()
    .options(wireMockConfig().dynamicPort())
    .build();

  @RegisterExtension
  WireMockExtension proxyMock = WireMockExtension.newInstance()
    .options(wireMockConfig().dynamicPort())
    .build();

  @BeforeEach
  void configureMocks() {
    proxyMock.stubFor(get(urlMatching(".*"))
      .inScenario("Proxy Auth")
      .whenScenarioStateIs(STARTED)
      .willReturn(aResponse()
        .withStatus(407)
        .withHeader("Proxy-Authenticate", "Basic realm=\"Access to the proxy\"")
      )
      .willSetStateTo("Challenge returned")
    );
    proxyMock.stubFor(get(urlMatching(".*"))
      .inScenario("Proxy Auth")
      .whenScenarioStateIs("Challenge returned")
      .willReturn(aResponse().proxiedFrom(serverMock.baseUrl())));

    serverMock.stubFor(get(urlMatching(".*"))
      .willReturn(aResponse().withStatus(200)));
  }

  @Test
  void testPreemptiveAuthToServerWithoutProxy() throws ExecutionException, InterruptedException {
    var client = java.net.http.HttpClient.newBuilder()
      .version(java.net.http.HttpClient.Version.HTTP_1_1)
      .build();

    var plainCreds = "user:pwd";
    var encoded = java.util.Base64.getEncoder().encodeToString(plainCreds.getBytes(StandardCharsets.UTF_8));
    var request = HttpRequest.newBuilder().uri(URI.create(serverMock.baseUrl() + "/some_url"))
      .setHeader("User-Agent", "myUserAgent")
      .setHeader("Authorization", "Basic " + encoded)
      .build();

    var call = client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
    var response = call.get();

    assertEquals(200, response.statusCode());

    serverMock.verify(getRequestedFor(urlEqualTo("/some_url"))
      .withHeader("User-Agent", equalTo("myUserAgent"))
      .withHeader("Authorization", containing("Basic")));

  }

  @Test
  void testPreemptiveAuthToServerWithChallengeAuthToProxy() throws ExecutionException, InterruptedException {
    var client = java.net.http.HttpClient.newBuilder()
      .version(java.net.http.HttpClient.Version.HTTP_1_1)
      .proxy(new ProxySelector() {
        @Override
        public List<Proxy> select(URI uri) {
          return List.of(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", proxyMock.getPort())));
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {

        }
      })
      .authenticator(new Authenticator() {
        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
          if (getRequestorType() != RequestorType.PROXY) {
            // We only want to handle proxy authentication here
            return null;
          }
          return new PasswordAuthentication("proxyUser", "proxyPwd".toCharArray());
        }
      })
      .build();

    var plainCreds = "user:pwd";
    var encoded = java.util.Base64.getEncoder().encodeToString(plainCreds.getBytes(StandardCharsets.UTF_8));
    var request = HttpRequest.newBuilder().uri(URI.create(serverMock.baseUrl() + "/some_url"))
      .setHeader("User-Agent", "myUserAgent")
      .setHeader("Authorization", "Basic " + encoded)
      .build();

    var call = client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
    var response = call.get();

    assertEquals(200, response.statusCode());

    proxyMock.verify(getRequestedFor(urlEqualTo("/some_url"))
      .withHeader("Proxy-Authorization", containing("Basic")));

    serverMock.verify(getRequestedFor(urlEqualTo("/some_url"))
      .withHeader("User-Agent", equalTo("myUserAgent"))
      .withHeader("Authorization", containing("Basic")));

  }
}
