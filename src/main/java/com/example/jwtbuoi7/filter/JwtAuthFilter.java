package com.example.jwtbuoi7.filter;

import com.example.jwtbuoi7.service.CustomUserDetailsService;
import com.example.jwtbuoi7.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtAuthFilter(JwtService jwtService, CustomUserDetailsService customUserDetailsService) {
        this.jwtService = jwtService;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7); // Loại bỏ "Bearer "
            username = jwtService.extractUsername(token); // Lấy tên người dùng từ token
            System.out.println("Extracted Token: " + token); // Log token
            System.out.println("Extracted Username: " + username); // Log username
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Kiểm tra nếu username không null và chưa có đối tượng xác thực trong SecurityContext
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
            // Lấy thông tin người dùng từ dịch vụ dựa trên username

            if (jwtService.validateToken(token, userDetails)) {
                // Kiểm tra xem token có hợp lệ với thông tin người dùng hay không

                String role = jwtService.extractRole(token);
                // Trích xuất vai trò (role) của người dùng từ token

                System.out.println("Extracted Role: " + role);
                // Log ra vai trò để kiểm tra trong quá trình phát triển

                List<GrantedAuthority> authorities = new ArrayList<>(userDetails.getAuthorities());
                // Lấy danh sách quyền hiện tại của người dùng từ UserDetails
                // Tạo danh sách quyền mới để có thể thêm các quyền bổ sung

                if (role != null && !role.trim().isEmpty()) {
                    // Kiểm tra vai trò có hợp lệ (không null    hoặc rỗng)

                    if (!role.startsWith("ROLE_")) {
                        // Kiểm tra nếu vai trò chưa có tiền tố "ROLE_", thêm vào
                        role = "ROLE_" + role;
                    }

            }
        }

        filterChain.doFilter(request, response);
    // Tiếp tục chuỗi filter để các filter hoặc xử lý tiếp theo có thể được thực thi

    }
    }
}

