package dev.limjustin.jwtsecuprac.service;

import dev.limjustin.jwtsecuprac.config.WebSecurityConfig;
import dev.limjustin.jwtsecuprac.dao.UserRepository;
import dev.limjustin.jwtsecuprac.model.UserDAO;
import dev.limjustin.jwtsecuprac.model.UserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@RequiredArgsConstructor
@Service
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    // private final BCryptPasswordEncoder bCryptPasswordEncoder;  // Circular References Issue

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserDAO findUser = userRepository.findByUsername(username);

        if (findUser == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        return new org.springframework.security.core.userdetails.User(findUser.getUsername(), findUser.getPassword(), new ArrayList<>());
    }

    public UserDAO save(UserDTO userDTO) {
        UserDAO newUser = new UserDAO();
        newUser.setUsername(userDTO.getUsername());
        newUser.setPassword(WebSecurityConfig.bCryptPasswordEncoder().encode(userDTO.getPassword()));
        return userRepository.save(newUser);
    }
}
