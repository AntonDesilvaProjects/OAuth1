package com.oauth1;

import com.github.scribejava.apis.TwitterApi;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.*;
import com.github.scribejava.core.oauth.OAuth10aService;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;

public class Runner {

    final static String TWITTER_CONSUMER_KEY = "";
    final static String TWITTER_CONSUMER_SECRET = "";

    final static String FLICKR_CONSUMER_KEY = "";
    final static String FLICKR_CONSUMER_SECRET = "";

    public static void main(String... args) throws InterruptedException, ExecutionException, IOException {

//        OAuth1Service oAuth1Service = new OAuth1Service();
//
//        HttpRequest request = new HttpRequest();
//        request.setHeaders(Map.of("Content-Type", List.of("application/x-www-form-urlencodexd")));
//        request.setUrl("https://api.twitter.com/1.1/account/verify_credentials.json");
//        request.setMethod(HttpRequest.Method.GET);
//        request.setBody("status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21");
//
//        String header = oAuth1Service.buildAuthorizationHeader(request, "",
//                "",
//                "",
//                "", null);
//        System.out.println(header);

        oauth1AuthorizationCode_flickr();

        //scribeJava();
    }

    public static void oauth1AuthorizationCode_twitter() throws IOException {
        final OAuth1Service oAuth1Service = new OAuth1Service();
        final OkHttpClient client = new OkHttpClient();

        final String requestTokenUrl = "https://api.twitter.com/oauth/request_token";
        final String authorizationUrl = "https://api.twitter.com/oauth/authorize";
        final String accessTokenUrl = "https://api.twitter.com/oauth/access_token";

        HttpRequest tokenRequest = new HttpRequest();
        tokenRequest.setUrl(requestTokenUrl);
        tokenRequest.setMethod(HttpRequest.Method.POST);

        String tokenRequestHeader = oAuth1Service.buildAuthorizationHeader(tokenRequest, TWITTER_CONSUMER_KEY,
                TWITTER_CONSUMER_SECRET,
                null,
                null, List.of(new Param("oauth_callback", "oob")));
        Request request = new Request.Builder()
                .url(requestTokenUrl)
                .post(RequestBody.create(null, ""))
                .addHeader("Authorization", tokenRequestHeader)
                .build();
        com.squareup.okhttp.Response response = client.newCall(request).execute();
        String rawTokenResponse = response.body().string();
        System.out.println("Token Response:\n" + rawTokenResponse);
        Map<String, String> tokenResponse = formEncodedStringToMap(rawTokenResponse);

        System.out.println("Login to Twitter at:" + authorizationUrl + "?oauth_token=" + tokenResponse.get("oauth_token"));
        System.out.print("Enter Verifier: ");
        final String verifier = new Scanner(System.in).nextLine();

        HttpRequest accessTokenRequest = new HttpRequest();
        accessTokenRequest.setUrl(accessTokenUrl);
        accessTokenRequest.setMethod(HttpRequest.Method.POST);

        final String token = tokenResponse.get("oauth_token");
        final String tokenSecret = tokenResponse.get("oauth_token_secret");

        String accessTokenHeader = oAuth1Service.buildAuthorizationHeader(accessTokenRequest, TWITTER_CONSUMER_KEY,
                TWITTER_CONSUMER_SECRET,
                token,
                tokenSecret,
                List.of(new Param("oauth_verifier", verifier)));
        request = new Request.Builder()
                .url(accessTokenUrl)
                .post(RequestBody.create(null, ""))
                .addHeader("Authorization", accessTokenHeader)
                .build();
        response = client.newCall(request).execute();
        String rawAccessTokenResponse = response.body().string();
        System.out.println("Access Token Response:\n" + rawAccessTokenResponse);
        Map<String, String> accessTokenResponse = formEncodedStringToMap(rawAccessTokenResponse);


        HttpRequest apiCall = new HttpRequest();
        apiCall.setUrl("https://api.twitter.com/1.1/account/verify_credentials.json");
        apiCall.setMethod(HttpRequest.Method.GET);

        final String accessToken = accessTokenResponse.get("oauth_token");
        final String accessTokenSecret = accessTokenResponse.get("oauth_token_secret");

        String apiCallHeader = oAuth1Service.buildAuthorizationHeader(apiCall, TWITTER_CONSUMER_KEY,
                TWITTER_CONSUMER_SECRET,
                accessToken,
                accessTokenSecret,
                List.of());
        request = new Request.Builder()
                .url("https://api.twitter.com/1.1/account/verify_credentials.json")
                .get()
                .addHeader("Authorization", apiCallHeader)
                .build();
        response = client.newCall(request).execute();
        String rawApiResponse = response.body().string();
        System.out.println("API Response:\n" + rawApiResponse);
    }

    public static void oauth1AuthorizationCode_flickr() throws IOException {
        final OAuth1Service oAuth1Service = new OAuth1Service();
        final OkHttpClient client = new OkHttpClient();

        final String requestTokenUrl = "https://www.flickr.com/services/oauth/request_token";
        final String authorizationUrl = "https://www.flickr.com/services/oauth/authorize";
        final String accessTokenUrl = "https://www.flickr.com/services/oauth/access_token";

        HttpRequest tokenRequest = new HttpRequest();
        tokenRequest.setUrl(requestTokenUrl);
        tokenRequest.setMethod(HttpRequest.Method.POST);

        String tokenRequestHeader = oAuth1Service.buildAuthorizationHeader(tokenRequest, FLICKR_CONSUMER_KEY,
                FLICKR_CONSUMER_SECRET,
                null,
                null, List.of(new Param("oauth_callback", "http://www.example.com/")));
        Request request = new Request.Builder()
                .url(requestTokenUrl)
                .post(RequestBody.create(null, ""))
                .addHeader("Authorization", tokenRequestHeader)
                .build();
        com.squareup.okhttp.Response response = client.newCall(request).execute();
        String rawTokenResponse = response.body().string();
        System.out.println("Token Response:\n" + rawTokenResponse);
        Map<String, String> tokenResponse = formEncodedStringToMap(rawTokenResponse);

        System.out.println("Login to Twitter at:" + authorizationUrl + "?oauth_token=" + tokenResponse.get("oauth_token") + "&perms=read");
        System.out.print("Enter Verifier: ");
        final String verifier = new Scanner(System.in).nextLine();

        HttpRequest accessTokenRequest = new HttpRequest();
        accessTokenRequest.setUrl(accessTokenUrl);
        accessTokenRequest.setMethod(HttpRequest.Method.POST);

        final String token = tokenResponse.get("oauth_token");
        final String tokenSecret = tokenResponse.get("oauth_token_secret");

        String accessTokenHeader = oAuth1Service.buildAuthorizationHeader(accessTokenRequest, FLICKR_CONSUMER_KEY,
                FLICKR_CONSUMER_SECRET,
                token,
                tokenSecret,
                List.of(new Param("oauth_verifier", verifier)));
        request = new Request.Builder()
                .url(accessTokenUrl)
                .post(RequestBody.create(null, ""))
                .addHeader("Authorization", accessTokenHeader)
                .build();
        response = client.newCall(request).execute();
        String rawAccessTokenResponse = response.body().string();
        System.out.println("Access Token Response:\n" + rawAccessTokenResponse);
        Map<String, String> accessTokenResponse = formEncodedStringToMap(rawAccessTokenResponse);


        final String accessToken = accessTokenResponse.get("oauth_token");
        final String accessTokenSecret = accessTokenResponse.get("oauth_token_secret");

        HttpRequest apiCall = new HttpRequest();
        apiCall.setUrl("https://www.flickr.com/services/rest?method=flickr.test.login");
        apiCall.setMethod(HttpRequest.Method.GET);

        String apiCallHeader = oAuth1Service.buildAuthorizationHeader(apiCall, FLICKR_CONSUMER_KEY,
                FLICKR_CONSUMER_SECRET,
                accessToken,
                accessTokenSecret,
                List.of());
        request = new Request.Builder()
                .url("https://www.flickr.com/services/rest?method=flickr.test.login")
                .get()
                .addHeader("Authorization", apiCallHeader)
                .build();
        response = client.newCall(request).execute();
        String rawApiResponse = response.body().string();
        System.out.println("API Response:\n" + rawApiResponse);
    }

    private static Map<String, String> formEncodedStringToMap(String s) {
        Map<String, String> keyValues = new HashMap<>();
        String[] pairs = s.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=");
            keyValues.put(kv[0], kv[1]);
        }
        return keyValues;
    }

    public static void scribeJava() throws IOException, ExecutionException, InterruptedException {
        final OAuth10aService service = new ServiceBuilder("")
                .apiSecret("")
                .debug()
                .build(TwitterApi.instance());
//        final Scanner in = new Scanner(System.in);
//
//        System.out.println("=== Twitter's OAuth Workflow ===");
//        System.out.println();
//
//        // Obtain the Request Token
//        System.out.println("Fetching the Request Token...");
//        final OAuth1RequestToken requestToken = service.getRequestToken();
//        System.out.println("Got the Request Token!");
//        System.out.println();
//
//        System.out.println("Now go and authorize ScribeJava here:");
//        System.out.println(service.getAuthorizationUrl(requestToken));
//        System.out.println("And paste the verifier here");
//        System.out.print(">>");
//        final String oauthVerifier = in.nextLine();
//        System.out.println();
//
//        // Trade the Request Token and Verifier for the Access Token
//        System.out.println("Trading the Request Token for an Access Token...");
//        final OAuth1AccessToken accessToken = service.getAccessToken(requestToken, oauthVerifier);
//        System.out.println("Got the Access Token!");
//        System.out.println("(The raw response looks like this: " + accessToken.getRawResponse() + "')");
//        System.out.println();

        final OAuth1AccessToken accessToken = new OAuth1AccessToken("1845821114-HKiH4X0BYpuO33dvHtV2QVQ3IhWscJFSNzkBxp1", "heVyVnmbEYYLiTNGELPObmyQGLPMnBmuxSgdbHpvK8FLh");

        // Now let's go and ask for a protected resource!
        System.out.println("Now we're going to access a protected resource...");
        final OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.twitter.com/1.1/account/verify_credentials.json");
        service.signRequest(accessToken, request);
        System.out.println(request.getHeaders().get("Authorization"));
        try (Response response = service.execute(request)) {
            System.out.println("Got it! Lets see what we found...");
            System.out.println();
            System.out.println(response.getBody());
        }
        System.out.println();
        System.out.println("That's it man! Go and build something awesome with ScribeJava! :)");
    }
}
