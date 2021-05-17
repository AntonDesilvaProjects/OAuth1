package com.oauth1;

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

    public String buildSignature(HttpRequest request, String consumerKey, String consumerSecret, String accessToken, String tokenSecret) {
        return null;
    }

    private String generateBaseString(HttpRequest request, String consumerKey, String accessToken) {
        List<Param> params = getStandardOAuthParams(consumerKey);

        // extract url params
        List<Param> queryParams = getQueryParams(request);
        params.addAll(queryParams);
        // extract any form URL encode values from body
        List<Param> bodyParams = getBodyParams(request);
        params.addAll(bodyParams);

        // first, url encode each key-value pair
        params = params.stream().map(param -> new Param(URLEncoder.encode(param.getName(), StandardCharsets.UTF_8),
                URLEncoder.encode(String.valueOf(param.getValue()), StandardCharsets.UTF_8)))
                .collect(Collectors.toList());
        // sort the params
        params = params.stream().sorted().collect(Collectors.toList());

        String baseString = params.stream().map(param -> param.getName() + "=" + param.getValue()).collect(Collectors.joining("&"));

        return baseString;
    }

    private List<Param> getStandardOAuthParams(String consumerKey) {
        List<Param> params = new ArrayList<>();
        params.add(new Param("oauth_consumer_key", consumerKey));
        params.add(new Param("oauth_nonce", UUID.randomUUID().toString()));
        params.add(new Param("oauth_signature_method", "HMAC-SHA1"));
        params.add(new Param("oauth_timestamp", Instant.now().getEpochSecond()));
        //params.put("oauth_token", consumerKey);
        params.add(new Param("oauth_version", 1.0));
        return params;
    }

    private List<Param> getQueryParams(HttpRequest request) {
        List<Param> params = new ArrayList<>();
        try {
            List<NameValuePair> urlParams = URLEncodedUtils
                    .parse(new URI(request.getUrl()), StandardCharsets.UTF_8);
            for (NameValuePair pair : urlParams) {
                params.add(new Param(pair.getName(), pair.getValue()));
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid url " + e.getMessage(), e);
        }

        // also add any query params
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
        List<Param> params = new ArrayList<>();
        final String body = request.getBody();
        String[] urlEncodedParams = body.split("&");
        for (String encodedPair : urlEncodedParams) {
            String[] pair = encodedPair.split("=");
            String decodedName = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            String decodedValue = URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            params.add(new Param(decodedName, decodedValue));
        }
        return params;
    }
}
