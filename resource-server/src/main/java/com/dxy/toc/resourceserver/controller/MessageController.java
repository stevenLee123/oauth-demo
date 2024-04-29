package com.dxy.toc.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author lijie3
 * @description
 * @date 2024/3/26 14:57
 */
@RestController
@RequestMapping("/web")
public class MessageController {

    @GetMapping("/message1")
    public String getMessage1(){
        return "hello 1";
    }
    @GetMapping("/message2")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public String getMessage2(){
        return "hello 2";
    }

    @GetMapping("/message3")
    @PreAuthorize("hasAuthority('SCOPE_message')")
    public String getMessage3(){
        return "hello 3";
    }



}
