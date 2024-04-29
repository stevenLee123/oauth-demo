package com.dxy.toc.authorization.endpoint;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author lijie3
 * @description
 * @date 2024/3/18 23:10
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/info")
    public JSONObject user(){
        JSONObject jsonObject = new JSONObject();
        final SecurityContext context = SecurityContextHolder.getContext();
        jsonObject.put("username",context.getAuthentication().getName());
        return jsonObject;
    }
}
