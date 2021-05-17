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

    public String buildSignature(HttpRequest request, String consumerKey, String consumerSecret, String token, String tokenSecret) {
        String baseString =  generateBaseString(request, consumerKey, token);
        System.out.print(baseString);
        String secret = percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret);
        return new String(new HmacUtils(HmacAlgorithms.HMAC_SHA_1, secret.getBytes()).hmac(baseString.getBytes()), StandardCharsets.UTF_8);
    }

    private String generateBaseString(HttpRequest request, String consumerKey, String token) {
        String paramString = URLEncoder.encode(generateParameterString(request, consumerKey, token)).replace("+", "%20");
        String method = request.getMethod().name();
        // this should be just base url
        String url = URLEncoder.encode(request.getUrl(), StandardCharsets.UTF_8).replace("+", "%20");

        return method + "&" + url + "&" + paramString;
    }

    private String generateParameterString(HttpRequest request, String consumerKey, String token) {
        List<Param> params = getStandardOAuthParams(consumerKey, token);

        // extract url params
        List<Param> queryParams = getQueryParams(request);
        params.addAll(queryParams);
        // extract any form URL encode values from body
        List<Param> bodyParams = getBodyParams(request);
        params.addAll(bodyParams);

        // first, url encode each key-value pair
        params = params.stream().map(param -> new Param(URLEncoder.encode(param.getName(), StandardCharsets.UTF_8).replace("+", "%20"),
                URLEncoder.encode(String.valueOf(param.getValue()), StandardCharsets.UTF_8).replace("+", "%20")))
                .collect(Collectors.toList());
        // sort the params
        params = params.stream().sorted().collect(Collectors.toList());

        return params.stream().map(param -> param.getName() + "=" + param.getValue()).collect(Collectors.joining("&"));
    }

    private List<Param> getStandardOAuthParams(String consumerKey, String token) {
        List<Param> params = new ArrayList<>();
        params.add(new Param("oauth_consumer_key", consumerKey));
        params.add(new Param("oauth_nonce", UUID.randomUUID().toString()));
        params.add(new Param("oauth_signature_method", "HMAC-SHA1"));
        params.add(new Param("oauth_timestamp", String.valueOf(Instant.now().getEpochSecond())));
        params.add(new Param("oauth_version", "1.0"));

        if (token != null) {
            params.add(new Param("oauth_token", token));
        }

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

    private String percentEncode(String toEncode) {
        return URLEncoder.encode(toEncode, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
