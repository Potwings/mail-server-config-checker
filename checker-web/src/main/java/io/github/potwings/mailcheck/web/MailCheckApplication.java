package io.github.potwings.mailcheck.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MailCheckApplication {

    public static void main(String[] args) {
        SpringApplication.run(MailCheckApplication.class, args);
    }
}
