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
import java.util.*;
import java.util.stream.Collectors;

public class OAuth1Service {

    public String buildSignature(HttpRequest request, String consumerKey, String consumerSecret, String token, String tokenSecret) {
        String baseString = generateBaseString(request, consumerKey, token);
        String secret = percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret);
        byte[] signature = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, secret.getBytes()).hmac(baseString.getBytes());
        return Base64.getEncoder().encodeToString(signature);
    }

    private String generateBaseString(HttpRequest request, String consumerKey, String token) {
        String method = request.getMethod().name();
        String url = percentEncode(getUrlWithoutParameters(request.getUrl()));
        String paramString = percentEncode(generateParameterString(request, consumerKey, token));
        return method.concat("&").concat(url).concat("&").concat(paramString);
    }

    private String generateParameterString(HttpRequest request, String consumerKey, String token) {
        // get the standard set of params that will always be there
        List<Param> params = getStandardOAuthParams(consumerKey, token);

        // extract url params
        List<Param> queryParams = getQueryParams(request);
        params.addAll(queryParams);

        // extract any form URL encode values from body
        List<Param> bodyParams = getBodyParams(request);
        params.addAll(bodyParams);

        // first, url encode each key-value pair
        params = params.stream()
                .map(param -> new Param(percentEncode(param.getName()), percentEncode(param.getValue())))
                .collect(Collectors.toList());
        // sort the params
        params = params.stream().sorted().collect(Collectors.toList());

        return params.stream()
                .map(param -> param.getName() + "=" + param.getValue())
                .collect(Collectors.joining("&"));
    }

    private List<Param> getStandardOAuthParams(String consumerKey, String token) {
        List<Param> params = new ArrayList<>();
        params.add(new Param("oauth_consumer_key", consumerKey));
        params.add(new Param("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"/*UUID.randomUUID().toString())*/));
        params.add(new Param("oauth_signature_method", "HMAC-SHA1"));
        params.add(new Param("oauth_timestamp", "1318622958" /*String.valueOf(Instant.now().getEpochSecond()))*/));
        params.add(new Param("oauth_version", "1.0"));

        if (token != null) {
            params.add(new Param("oauth_token", token));
        }

        return params;
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

    private String getUrlWithoutParameters(String url) {
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
