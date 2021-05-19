package com.oauth1;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class OAuth1Service {

    public static final String AMPERSAND = "&";
    public static final String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
    public static final String OAUTH_NONCE = "oauth_nonce";
    public static final String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
    public static final String OAUTH_TIMESTAMP = "oauth_timestamp";
    public static final String OAUTH_VERSION = "oauth_version";
    public static final String OAUTH_TOKEN = "oauth_token";
    public static final String HMAC_SHA_1 = "HMAC-SHA1";
    public static final String VERSION = "1.0";
    public static final String OAUTH_SIGNATURE = "oauth_signature";

    public List<Param> generateOAuthParams(HttpRequest request,
                                           String consumerKey, String consumerSecret,
                                           String token, String tokenSecret,
                                           List<Param> customParams) {

        // first generate the standard params
        List<Param> params = new ArrayList<>(Optional.ofNullable(customParams).orElse(new ArrayList<>()));
        params.add(new Param(OAUTH_CONSUMER_KEY, consumerKey));
        params.add(new Param(OAUTH_NONCE, UUID.randomUUID().toString()));
        params.add(new Param(OAUTH_SIGNATURE_METHOD, HMAC_SHA_1));
        params.add(new Param(OAUTH_TIMESTAMP, String.valueOf(Instant.now().getEpochSecond())));
        params.add(new Param(OAUTH_VERSION, VERSION));

        // we might not always a oauth_token(e.g. during the Request Token call) so set if available
        if (token != null) {
            params.add(new Param(OAUTH_TOKEN, token));
        }

        // use all of the above params to build the signature
        final String method = request.getMethod().name();
        final String url = percentEncode(getUrlWithoutQueryParams(request.getUrl()));
        final String paramString = percentEncode(generateParameterString(request, params));
        final String baseString = method.concat(AMPERSAND).concat(url).concat(AMPERSAND).concat(paramString);

        final String secret = percentEncode(consumerSecret).concat(AMPERSAND)
                .concat(percentEncode(tokenSecret == null ? "" : tokenSecret));
        final byte[] signatureBytes = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, secret.getBytes()).hmac(baseString.getBytes());
        final String signature = Base64.getEncoder().encodeToString(signatureBytes);

        params.add(new Param(OAUTH_SIGNATURE, signature));

        return params;
    }

    public String buildAuthorizationHeader(HttpRequest request,
                                           String consumerKey, String consumerSecret,
                                           String token, String tokenSecret,
                                           List<Param> customParams) {
        final List<Param> params = generateOAuthParams(request, consumerKey, consumerSecret, token, tokenSecret, customParams);
        return "OAuth " + params.stream()
                .map(param -> percentEncode(param.getName())
                        .concat("=")
                        .concat("\"")
                            .concat(percentEncode(param.getValue()))
                        .concat("\""))
                .collect(Collectors.joining(", "));
    }


    private String generateParameterString(HttpRequest request, List<Param> params) {
        List<Param> paramsList = new ArrayList<>(params);

        // extract url params
        List<Param> queryParams = getQueryParams(request);
        paramsList.addAll(queryParams);

        // extract any form URL encode values from body
        List<Param> bodyParams = getBodyParams(request);
        paramsList.addAll(bodyParams);

        // url encode each key-value pair
        paramsList = paramsList.stream()
                .map(param -> new Param(percentEncode(param.getName()), percentEncode(param.getValue())))
                .collect(Collectors.toList());

        // sort the params lexicographically
        paramsList = paramsList.stream().sorted().collect(Collectors.toList());

        // join all params
        return paramsList.stream()
                .map(param -> param.getName() + "=" + param.getValue())
                .collect(Collectors.joining("&"));
    }


    private List<Param> getQueryParams(HttpRequest request) {
        final List<Param> params = new ArrayList<>();

        // extract any query params that may be in the URL already
        try {
            List<NameValuePair> urlParams = URLEncodedUtils.parse(new URI(request.getUrl()), StandardCharsets.UTF_8);
            for (NameValuePair pair : urlParams) {
                params.add(new Param(pair.getName(), pair.getValue()));
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid url " + e.getMessage(), e);
        }

        // also add any query params that are supplied separately
        if (request.getQueryParams() != null) {
            for (Map.Entry<String, List<String>> entry : request.getQueryParams().entrySet()) {
                List<String> values = entry.getValue();
                for (String value : values) {
                    params.add(new Param(entry.getKey(), value));
                }
            }
        }
        return params;
    }

    private List<Param> getBodyParams(HttpRequest request) {
        final List<Param> params = new ArrayList<>();
        final Map<String, List<String>> headers =request.getHeaders();
        if (headers != null) {
            final List<String> contentType = headers.get("Content-Type");
            if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
                final String body = request.getBody();
                String[] urlEncodedParams = body.split("&");
                for (String encodedPair : urlEncodedParams) {
                    String[] pair = encodedPair.split("=");
                    String decodedName = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                    String decodedValue = URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                    params.add(new Param(decodedName, decodedValue));
                }
            }
        }
        return params;
    }

    private String percentEncode(String toEncode) {
        return URLEncoder.encode(toEncode, StandardCharsets.UTF_8)
                .replace("+", "%20");
    }

    private String getUrlWithoutQueryParams(String url) {
        try {
            URI uri = new URI(url);
            return new URI(uri.getScheme(),
                    uri.getAuthority(),
                    uri.getPath(),
                    null, // Ignore the query part of the input url
                    uri.getFragment()).toString();
        } catch (URISyntaxException u) {
            throw new IllegalArgumentException("Invalid URL!");
        }
    }
}
