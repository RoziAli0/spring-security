package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.Exception.AppException;
import com.example.springsecurityjwt.model.Role;
import com.example.springsecurityjwt.model.RoleName;
import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.payload.ApiResponse;
import com.example.springsecurityjwt.payload.JwtAuthenticationResponse;
import com.example.springsecurityjwt.payload.LoginRequest;
import com.example.springsecurityjwt.payload.SignupRequest;
import com.example.springsecurityjwt.repository.RoleRepository;
import com.example.springsecurityjwt.repository.UserRepository;
import com.example.springsecurityjwt.security.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenProvider jwtTokenProvider;

    @Autowired
    RoleRepository roleRepository;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getPassword(),
                        loginRequest.getUsernameOrEmail()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtTokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest)
    {
        if(userRepository.existsByUsername(signupRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, "Username is alraedy taken!"),
                    HttpStatus.BAD_REQUEST);
        }
        if(userRepository.existsByEmail(signupRequest.getEmail())){
            return new ResponseEntity(new ApiResponse(false, "Email is already taken!"), HttpStatus.BAD_REQUEST);
        }
        User user = new User(signupRequest.getName(), signupRequest.getUsername(), signupRequest.getEmail(),
                signupRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER).orElseThrow(()->new AppException("User Role not set"));

        user.setRoles(Collections.singleton(userRole));
        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder.fromCurrentContextPath().path("user/{username}")
                .buildAndExpand(result.getUsername()).toUri();

        return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));
    }
}
