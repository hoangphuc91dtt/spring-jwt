package com.example.jwtbuoi7.controller;

import com.example.jwtbuoi7.entity.AuthRequest;
import com.example.jwtbuoi7.entity.UserInfo;
import com.example.jwtbuoi7.service.JwtService;
import com.example.jwtbuoi7.service.UserInfoDetails;
import com.example.jwtbuoi7.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserInfoService service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;


    // Endpoint to get user details by email
    @GetMapping("/getUserDetails")
    public UserInfoDetails getUserDetails(@RequestParam String email) {
        // Call the service to get UserDetails by email
        UserInfoDetails userInfoDetails = (UserInfoDetails) service.loadUserByUsername(email);
        return userInfoDetails; // Return the UserInfoDetails
    }
    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    @PostMapping("/addNewUser")
    public String addNewUser(@RequestBody UserInfo userInfo) {
        return service.addUser(userInfo);
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String userProfile() {
        return "Welcome to User Profile";
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminProfile() {
        return "Welcome to Admin Profile";
    }

    @PostMapping("/generateToken")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
        if (authentication.isAuthenticated()) {
            // Lấy thông tin UserDetails
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Lấy role từ UserDetails (hoặc từ UserInfo nếu bạn có thông tin này ở đó)
            String role = userDetails.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .findFirst()
                    .orElse("USER"); // Nếu không có vai trò, mặc định là "USER"

            // Gọi jwtService.generateToken với cả username và role
            return jwtService.generateToken(authRequest.getUsername(), role);
        } else {
            throw new UsernameNotFoundException("Invalid user request!");
        }
    }
}
