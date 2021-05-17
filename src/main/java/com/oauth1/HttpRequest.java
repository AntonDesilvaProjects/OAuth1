package com.oauth1;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpRequest {
    enum Method {
        GET, PUT, POST, DELETE
    }
    private String url;
    private Method method;
    private Map<String, List<String>> headers;
    private Map<String, List<String>> queryParams;
    private String body;

    public void addHeader(String name, String value) {
        if (headers == null) {
            headers = new HashMap<>();
        }
        if (headers.containsKey(name)) {
            headers.get(name).add(value);
        } else {
            List<String> values = new ArrayList<>();
            values.add(value);
            headers.put(name, values);
        }
    }

    public void addQueryParam(String name, String value) {
        if (queryParams == null) {
            queryParams = new HashMap<>();
        }
        if (queryParams.containsKey(name)) {
            queryParams.get(name).add(value);
        } else {
            List<String> values = new ArrayList<>();
            values.add(value);
            queryParams.put(name, values);
        }
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Method getMethod() {
        return method;
    }

    public void setMethod(Method method) {
        this.method = method;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public Map<String, List<String>> getQueryParams() {
        return queryParams;
    }

    public void setQueryParams(Map<String, List<String>> queryParams) {
        this.queryParams = queryParams;
    }
}
