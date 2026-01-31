package dev.lavalink.youtube.http;

import com.sedmelluq.discord.lavaplayer.tools.http.HttpContextRetryCounter;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpClientTools;
import com.sedmelluq.discord.lavaplayer.tools.DataFormatTools;
import dev.lavalink.youtube.clients.skeleton.Client;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static dev.lavalink.youtube.http.YoutubeOauth2Handler.OAUTH_INJECT_CONTEXT_ATTRIBUTE;

public class YoutubeHttpContextFilter extends BaseYoutubeHttpContextFilter {
  private static final Logger log = LoggerFactory.getLogger(YoutubeHttpContextFilter.class);

  private static final String ATTRIBUTE_RESET_RETRY = "isResetRetry";
  public static final String ATTRIBUTE_USER_AGENT_SPECIFIED = "clientUserAgent";
  public static final String ATTRIBUTE_VISITOR_DATA_SPECIFIED = "clientVisitorData";
  public static final String ATTRIBUTE_CIPHER_REQUEST_SPECIFIED = "remoteCipherRequest";

  // Context attributes for debug saving
  private static final String ATTRIBUTE_DEBUG_REQUEST_INFO_REDACTED = "debugRequestInfoRedacted";
  private static final String ATTRIBUTE_DEBUG_REQUEST_INFO_RAW = "debugRequestInfoRaw";

  // Sensitive query params to redact
  private static final Pattern SENSITIVE_QUERY_PARAMS = Pattern.compile(
      "(access_token|token|oauth_token|refresh_token|key|sig|signature)=([^&]*)",
      Pattern.CASE_INSENSITIVE
  );

  // Sensitive JSON fields to redact
  private static final Pattern SENSITIVE_JSON_FIELDS = Pattern.compile(
      "(\"(?:access_token|oauth_token|token|refresh_token|authorization|sig|signature)\"\\s*:\\s*)\"[^\"]*\"",
      Pattern.CASE_INSENSITIVE
  );

  private static final HttpContextRetryCounter retryCounter = new HttpContextRetryCounter("yt-token-retry");
  private static final AtomicLong debugFileCounter = new AtomicLong(0);

  private YoutubeAccessTokenTracker tokenTracker;
  private YoutubeOauth2Handler oauth2Handler;

  private String remoteCipherPass;
  private String remoteCipherUserAgent;
  private String pluginVersion;
  private String debugSaveResponsesDirectory;

  public void setTokenTracker(@NotNull YoutubeAccessTokenTracker tokenTracker) {
    this.tokenTracker = tokenTracker;
  }

  public void setOauth2Handler(@NotNull YoutubeOauth2Handler oauth2Handler) {
    this.oauth2Handler = oauth2Handler;
  }

  public void setCipherConfig(@Nullable String remotePass,
                              @Nullable String userAgent,
                              @NotNull String pluginVersion) {
    this.remoteCipherPass = remotePass;
    this.remoteCipherUserAgent = userAgent;
    this.pluginVersion = pluginVersion;
  }

  public void setDebugSaveResponsesDirectory(@Nullable String directory) {
    this.debugSaveResponsesDirectory = directory;
  }

  @Override
  public void onContextOpen(HttpClientContext context) {
    CookieStore cookieStore = context.getCookieStore();

    if (cookieStore == null) {
      cookieStore = new BasicCookieStore();
      context.setCookieStore(cookieStore);
    }

    // Reset cookies for each sequence of requests.
    cookieStore.clear();
  }

  @Override
  public void onRequest(HttpClientContext context,
                        HttpUriRequest request,
                        boolean isRepetition) {
    if (!isRepetition) {
      context.removeAttribute(ATTRIBUTE_RESET_RETRY);
    }

    retryCounter.handleUpdate(context, isRepetition);

    if (tokenTracker.isTokenFetchContext(context)) {
      // Used for fetching visitor id, let's not recurse.
      return;
    }

    if (oauth2Handler.isOauthFetchContext(context)) {
      return;
    }

    String userAgent = context.getAttribute(ATTRIBUTE_USER_AGENT_SPECIFIED, String.class);

    if (isRemoteCipherRequest(context)) {
      if (!DataFormatTools.isNullOrEmpty(remoteCipherPass)) {
        request.addHeader("Authorization", remoteCipherPass);
      }

      if (!DataFormatTools.isNullOrEmpty(remoteCipherUserAgent)) {
        request.addHeader("User-Agent", remoteCipherUserAgent);
      }

      request.addHeader("Plugin-Version", pluginVersion);
    } else if (!request.getURI().getHost().contains("googlevideo")) {
      if (userAgent != null) {
        request.setHeader("User-Agent", userAgent);

        String visitorData = context.getAttribute(ATTRIBUTE_VISITOR_DATA_SPECIFIED, String.class);
        request.setHeader("X-Goog-Visitor-Id", visitorData != null ? visitorData : tokenTracker.getVisitorId());

        context.removeAttribute(ATTRIBUTE_VISITOR_DATA_SPECIFIED);
        context.removeAttribute(ATTRIBUTE_USER_AGENT_SPECIFIED);
      }

      boolean isRequestFromOauthedClient = context.removeAttribute(Client.OAUTH_CLIENT_ATTRIBUTE) == Boolean.TRUE;

      if (isRequestFromOauthedClient && Client.PLAYER_URL.equals(request.getURI().toString())) {
        // Look at the userdata for any provided oauth-token
        String oauthToken = context.getAttribute(OAUTH_INJECT_CONTEXT_ATTRIBUTE, String.class);
        // only apply the token to /player requests.
        if (oauthToken != null && !oauthToken.isEmpty()) {
          oauth2Handler.applyToken(request, oauthToken);
        } else {
          oauth2Handler.applyToken(request);
        }
      }
    } else {
      // googlevideo.com: when formats were obtained with OAuth, the stream/segment requests
      // must also send the same auth or YouTube may return 403/error page instead of video,
      // causing decoding failures (e.g. "Expected decoding to halt, got: 5").
      String oauthToken = context.getAttribute(OAUTH_INJECT_CONTEXT_ATTRIBUTE, String.class);
      if (oauthToken != null && !oauthToken.isEmpty()) {
        oauth2Handler.applyToken(request, oauthToken);
      } else if (oauth2Handler.hasAccessToken()) {
        oauth2Handler.applyToken(request);
      }
      if (log.isDebugEnabled()) {
        boolean authPresent = request.getFirstHeader("Authorization") != null;
        log.debug("Stream request to googlevideo: uri={}, Authorization header present={}", request.getURI(), authPresent);
      }
    }

    // Capture request info for debug saving (after all headers are set)
    if (!DataFormatTools.isNullOrEmpty(debugSaveResponsesDirectory)) {
      String host = request.getURI().getHost();
      if (host != null && (host.contains("youtubei.googleapis.com") || host.contains("googlevideo"))) {
        try {
          String[] requestInfo = captureRequestInfo(request);
          context.setAttribute(ATTRIBUTE_DEBUG_REQUEST_INFO_REDACTED, requestInfo[0]);
          context.setAttribute(ATTRIBUTE_DEBUG_REQUEST_INFO_RAW, requestInfo[1]);
        } catch (Exception e) {
          log.warn("Failed to capture request info for debug saving", e);
        }
      }
    }

//    try {
//      URI uri = new URIBuilder(request.getURI())
//          .setParameter("key", YoutubeConstants.INNERTUBE_ANDROID_API_KEY)
//          .build();
//
//      if (request instanceof HttpRequestBase) {
//        ((HttpRequestBase) request).setURI(uri);
//      } else {
//        throw new IllegalStateException("Cannot update request URI.");
//      }
//    } catch (URISyntaxException e) {
//      throw new RuntimeException(e);
//    }
  }

  private static final int DEBUG_RESPONSE_HEAD_BYTES = 64;

  @Override
  public boolean onRequestResponse(HttpClientContext context,
                                   HttpUriRequest request,
                                   HttpResponse response) {
    String host = request.getURI().getHost();
    int status = response.getStatusLine().getStatusCode();

    // Debug logging for googlevideo
    if (log.isDebugEnabled() && host != null && host.contains("googlevideo")) {
      String contentType = response.getFirstHeader("Content-Type") != null
          ? response.getFirstHeader("Content-Type").getValue()
          : "(none)";
      log.debug("Stream response from googlevideo: uri={}, status={}, Content-Type={}", request.getURI(), status, contentType);
      if (status != 200) {
        HttpEntity entity = response.getEntity();
        if (entity != null) {
          try {
            byte[] body = EntityUtils.toByteArray(entity);
            response.setEntity(new ByteArrayEntity(body));
            int head = Math.min(DEBUG_RESPONSE_HEAD_BYTES, body.length);
            StringBuilder hex = new StringBuilder(head * 2);
            for (int i = 0; i < head; i++) {
              hex.append(String.format(Locale.ROOT, "%02x", body[i] & 0xff));
            }
            log.debug("Stream response first {} bytes (hex, status != 200): {}", head, hex);
          } catch (Exception e) {
            log.debug("Could not read stream response body for logging", e);
          }
        }
      }
    }

    // Debug save to files
    if (!DataFormatTools.isNullOrEmpty(debugSaveResponsesDirectory) &&
        host != null && (host.contains("youtubei.googleapis.com") || host.contains("googlevideo"))) {
      try {
        saveDebugFiles(context, request, response, host, status);
      } catch (Exception e) {
        log.warn("Failed to save debug files for request to {}", host, e);
      }
    }

    return false;
  }

  /**
   * Captures request info for debug saving, building both redacted and raw versions in a single pass.
   * @return String array: [0] = redacted, [1] = raw
   */
  private String[] captureRequestInfo(HttpUriRequest request) throws IOException {
    StringBuilder redacted = new StringBuilder();
    StringBuilder raw = new StringBuilder();

    // Method and URI
    String method = request.getMethod();
    String uriRaw = request.getURI().toString();
    String uriRedacted = redactUri(request.getURI());

    redacted.append(method).append(" ").append(uriRedacted).append("\n");
    raw.append(method).append(" ").append(uriRaw).append("\n");

    // Headers
    for (Header header : request.getAllHeaders()) {
      String name = header.getName();
      String value = header.getValue();

      raw.append(name).append(": ").append(value).append("\n");

      if ("Authorization".equalsIgnoreCase(name)) {
        redacted.append(name).append(": ***REDACTED***\n");
      } else {
        redacted.append(name).append(": ").append(value).append("\n");
      }
    }

    redacted.append("\n");
    raw.append("\n");

    // Request body (if repeatable)
    if (request instanceof HttpEntityEnclosingRequest) {
      HttpEntityEnclosingRequest entityRequest = (HttpEntityEnclosingRequest) request;
      HttpEntity entity = entityRequest.getEntity();
      if (entity != null && entity.isRepeatable()) {
        try {
          byte[] bodyBytes = EntityUtils.toByteArray(entity);
          String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);

          raw.append(bodyStr);
          redacted.append(redactJsonFields(bodyStr));
        } catch (Exception e) {
          String err = "[Request body could not be read: " + e.getMessage() + "]";
          redacted.append(err);
          raw.append(err);
        }
      } else if (entity != null) {
        String msg = "[Request body not repeatable, skipped]";
        redacted.append(msg);
        raw.append(msg);
      }
    }

    return new String[] { redacted.toString(), raw.toString() };
  }

  private String redactUri(URI uri) {
    String uriStr = uri.toString();
    return SENSITIVE_QUERY_PARAMS.matcher(uriStr).replaceAll("$1=***REDACTED***");
  }

  private String redactJsonFields(String json) {
    return SENSITIVE_JSON_FIELDS.matcher(json).replaceAll("$1\"***REDACTED***\"");
  }

  /**
   * Formats headers, building both redacted and raw versions in a single pass.
   * @return String array: [0] = redacted, [1] = raw
   */
  private String[] formatHeaders(Header[] headers) {
    StringBuilder redacted = new StringBuilder();
    StringBuilder raw = new StringBuilder();

    for (Header header : headers) {
      String name = header.getName();
      String value = header.getValue();

      raw.append(name).append(": ").append(value).append("\n");

      if ("Authorization".equalsIgnoreCase(name)) {
        redacted.append(name).append(": ***REDACTED***\n");
      } else {
        redacted.append(name).append(": ").append(value).append("\n");
      }
    }

    return new String[] { redacted.toString(), raw.toString() };
  }

  private void saveDebugFiles(HttpClientContext context,
                              HttpUriRequest request,
                              HttpResponse response,
                              String host,
                              int status) throws IOException {
    // Generate unique file prefix
    String hostPrefix = host.contains("googlevideo") ? "googlevideo" : "youtubei";
    long timestamp = System.currentTimeMillis();
    long counter = debugFileCounter.incrementAndGet();
    String prefix = String.format(Locale.ROOT, "%s_%d_%d_%d", hostPrefix, timestamp, status, counter);

    Path baseDir = Path.of(debugSaveResponsesDirectory);
    Path redactedDir = baseDir.resolve("redacted");
    Path rawDir = baseDir.resolve("raw");
    Files.createDirectories(redactedDir);
    Files.createDirectories(rawDir);

    // Write request files (both versions)
    String requestRedacted = context.getAttribute(ATTRIBUTE_DEBUG_REQUEST_INFO_REDACTED, String.class);
    String requestRaw = context.getAttribute(ATTRIBUTE_DEBUG_REQUEST_INFO_RAW, String.class);

    if (requestRedacted != null) {
      Files.writeString(redactedDir.resolve(prefix + "_request.txt"), requestRedacted, StandardCharsets.UTF_8);
    }
    if (requestRaw != null) {
      Files.writeString(rawDir.resolve(prefix + "_request.txt"), requestRaw, StandardCharsets.UTF_8);
    }

    // Read response body once
    HttpEntity entity = response.getEntity();
    byte[] responseBody = null;
    if (entity != null) {
      responseBody = EntityUtils.toByteArray(entity);
      response.setEntity(new ByteArrayEntity(responseBody));
    }

    // Format headers once (both versions)
    String[] headers = formatHeaders(response.getAllHeaders());
    String headersRedacted = headers[0];
    String headersRaw = headers[1];
    String statusLine = response.getStatusLine().toString();

    // Determine content type
    String contentType = response.getFirstHeader("Content-Type") != null
        ? response.getFirstHeader("Content-Type").getValue()
        : "";
    boolean isTextResponse = contentType.contains("json") || contentType.contains("text") || contentType.contains("html");
    boolean isGooglevideo = host.contains("googlevideo");

    if (isGooglevideo && !isTextResponse) {
      // Binary response: write meta file + body file separately
      String metaRedacted = statusLine + "\n" + headersRedacted;
      String metaRaw = statusLine + "\n" + headersRaw;

      Files.writeString(redactedDir.resolve(prefix + "_response_meta.txt"), metaRedacted, StandardCharsets.UTF_8);
      Files.writeString(rawDir.resolve(prefix + "_response_meta.txt"), metaRaw, StandardCharsets.UTF_8);

      if (responseBody != null) {
        String ext = contentType.contains("html") ? ".html" : ".bin";
        // Binary body is the same for both (no redaction needed for binary)
        Files.write(redactedDir.resolve(prefix + "_response_body" + ext), responseBody);
        Files.write(rawDir.resolve(prefix + "_response_body" + ext), responseBody);
      }
    } else {
      // Text response: write single response file with status, headers, and body
      String bodyRaw = responseBody != null ? new String(responseBody, StandardCharsets.UTF_8) : "";
      String bodyRedacted = redactJsonFields(bodyRaw);

      String ext = contentType.contains("html") ? ".html" : ".txt";

      String responseRedacted = statusLine + "\n" + headersRedacted + "\n" + bodyRedacted;
      String responseRaw = statusLine + "\n" + headersRaw + "\n" + bodyRaw;

      Files.writeString(redactedDir.resolve(prefix + "_response" + ext), responseRedacted, StandardCharsets.UTF_8);
      Files.writeString(rawDir.resolve(prefix + "_response" + ext), responseRaw, StandardCharsets.UTF_8);
    }
  }

  @Override
  public boolean onRequestException(HttpClientContext context,
                                    HttpUriRequest request,
                                    Throwable error) {
    // Always retry once in case of connection reset exception.
    if (HttpClientTools.isConnectionResetException(error)) {
      if (context.getAttribute(ATTRIBUTE_RESET_RETRY) == null) {
        context.setAttribute(ATTRIBUTE_RESET_RETRY, true);
        return true;
      }
    }

    return false;
  }

  private boolean isRemoteCipherRequest(HttpClientContext context) {
    return context.removeAttribute(ATTRIBUTE_CIPHER_REQUEST_SPECIFIED) == Boolean.TRUE;
  }
}
