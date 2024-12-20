package com.example.jwtbuoi7.config;

import com.example.jwtbuoi7.filter.JwtAuthFilter;
import com.example.jwtbuoi7.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter authFilter;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserInfoService(); // Ensure UserInfoService implements UserDetailsService
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**") // Tắt CSRF cho H2 Console
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/welcome", "/auth/addNewUser", "/auth/generateToken", "/h2-console/**")
                        .permitAll() // Cho phép truy cập công khai đến các endpoints
                        .requestMatchers("/auth/user/**").hasAuthority("ROLE_USER") // Chỉ cho phép người dùng có role USER truy cập
                        .requestMatchers("/auth/admin/**").hasAuthority("ROLE_ADMIN") // Chỉ cho phép người dùng có role ADMIN truy cập
                        .anyRequest().authenticated() // Các yêu cầu khác đều yêu cầu xác thực
                )
                .headers().frameOptions().sameOrigin() // Cho phép H2 console chạy trong iframe
                .and()
                .sessionManagement(sess -> sess
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Không sử dụng session cho API
                )
                .authenticationProvider(authenticationProvider()) // Sử dụng provider xác thực tùy chỉnh
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class); // Thêm JWT filter vào pipeline

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Định dạng mật khẩu cho người dùng
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService()); // Sử dụng service lấy thông tin người dùng
        authenticationProvider.setPasswordEncoder(passwordEncoder()); // Định dạng mật khẩu
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager(); // Cung cấp authentication manager
    }
}
