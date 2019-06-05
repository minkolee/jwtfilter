package cc.conyli.jwtfilter.controller;

import cc.conyli.jwtfilter.jwt.JWTUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class BaseController {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private JWTUtils jwtUtils;

    public BaseController(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @GetMapping
    private String homePage() {
        logger.info("Key String is |" + jwtUtils.getKeyString());
        logger.info("Key is " + jwtUtils.getKey());
        return "home";
    }
}
