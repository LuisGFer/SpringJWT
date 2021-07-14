package com.test.securityDB.model;
import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "sec_user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column( name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password")
    private String password;

}