package cc.conyli.jwtfilter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
//@ServletComponentScan
public class JwtfilterApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtfilterApplication.class, args);
    }

}
