package com.example.jwtbuoi7.service;

import com.example.jwtbuoi7.entity.UserInfo;
import com.example.jwtbuoi7.repository.UserInfoRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    private final UserInfoRepository repository;

    public CustomUserDetailsService(UserInfoRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Truy vấn người dùng từ repository
        UserInfo userInfo = repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Tạo đối tượng UserDetails với thông tin từ userInfo
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(userInfo.getRoles()));

        return new org.springframework.security.core.userdetails.User(userInfo.getEmail(), userInfo.getPassword(), authorities);
    }
}


