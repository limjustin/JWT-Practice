package dev.limjustin.jwtsecuprac.controller;

import dev.limjustin.jwtsecuprac.config.JwtTokenUtil;
import dev.limjustin.jwtsecuprac.model.JwtRequest;
import dev.limjustin.jwtsecuprac.model.JwtResponse;
import dev.limjustin.jwtsecuprac.service.JwtUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@CrossOrigin
public class JwtAuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final JwtUserDetailsService userDetailsService;

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
        System.out.println("JwtAuthenticationController.createAuthenticationToken");
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        System.out.println("authenticationRequest.getUsername() = " + authenticationRequest.getUsername());
        UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        String token = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(token));
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            System.out.println("authenticate.getPrincipal() = " + authenticate.getPrincipal());
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
