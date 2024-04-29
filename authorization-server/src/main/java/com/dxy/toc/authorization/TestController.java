package com.dxy.toc.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author lijie3
 * @description
 * @date 2024/3/18 17:53
 */
@RestController
@RequestMapping("/index")
public class TestController {

    @GetMapping("/hello")
    public Object index(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication;
    }
}
