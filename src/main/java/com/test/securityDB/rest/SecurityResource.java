package com.test.securityDB.rest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
public class SecurityResource {

    @GetMapping("publico")
    public String endpointPublico() {
        return "EndPoint público";
    }

    @GetMapping("privado")
    @PreAuthorize("hasRole('ADMIN')")
    public String endpointPrivado() {
        return "EndPoint privado";
    }

}
