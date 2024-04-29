package com.dxy.toc.oauthclient;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author lijie3
 * @description
 * @date 2024/3/19 17:54
 */
@RestController
@RequestMapping("")
public class TestController {

    @GetMapping("/token")
    public OAuth2AuthorizedClient token(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient){
        return oAuth2AuthorizedClient;
    }


}
