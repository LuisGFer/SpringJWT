package com.test.securityDB.security;

import com.test.securityDB.model.User;
import com.test.securityDB.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public AppUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = this.userRepository.findUserByUsername(username);

        // guarda de validacion
        if (user == null) {
            throw new UsernameNotFoundException("Usuario: " + username + " no encontrado");
        }

        // devolvemos UserDetails
        UserBuilder builder = null;
        builder = org.springframework.security.core.userdetails.User.withUsername(username);
        builder.password(new BCryptPasswordEncoder().encode(user.getPassword()));
        //builder.password(user.getPassword());
        builder.roles("ADMIN");

        return builder.build();
    }

    //@Bean
    //public PasswordEncoder passwordEncoder() {
    //    return new BCryptPasswordEncoder();
    //}
}
