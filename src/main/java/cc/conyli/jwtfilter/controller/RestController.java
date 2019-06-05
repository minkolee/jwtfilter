package cc.conyli.jwtfilter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@org.springframework.web.bind.annotation.RestController
@RequestMapping("/rest")
public class RestController {

    @GetMapping("/superuser")
    public String helloSuperUser() {
        return "Hello authenticated superuser";
    }

    @GetMapping("/user")
    public String helloUser() {
        return "Hello authenticated user";
    }

    @GetMapping("/admin")
    public String helloAdmin() {
        return "Hello authenticated admin";
    }
}
