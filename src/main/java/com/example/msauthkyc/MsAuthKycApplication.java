package com.example.msauthkyc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class MsAuthKycApplication {

    public static void main(String[] args) {
        SpringApplication.run(MsAuthKycApplication.class, args);
    }
}
