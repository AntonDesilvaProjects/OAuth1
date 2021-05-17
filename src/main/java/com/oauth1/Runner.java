package com.oauth1;

public class Runner {
    public static void main(String... args) {

        OAuth1Service oAuth1Service = new OAuth1Service();

        HttpRequest request = new HttpRequest();
        request.setUrl("https://api.twitter.com/1.1/statuses/update.json?include_entities=true");
        request.setMethod(HttpRequest.Method.POST);
        request.setBody("status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21");
        String s = oAuth1Service.buildSignature(request, "xvz1evFS4wEEPTGEFPHBog", "", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "");
        System.out.println(s);
    }
}
