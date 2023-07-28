package com.alibou.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()// Tắt chức năng bảo vệ CSRF
                .authorizeHttpRequests()// Bắt đầu cấu hình xác thực truy cập cho các yêu cầu HTTP
                .requestMatchers("/api/v1/**").permitAll()// Cho phép tất cả các yêu cầu truy cập vào các tài nguyên dưới thư mục /api/v1/ mà không cần xác thực.
                .anyRequest().authenticated()// Yêu cầu xác thực cho tất cả các yêu cầu không được khai báo trước đó. Điều này đảm bảo rằng những yêu cầu không nằm trong thư mục /api/v1/ sẽ yêu cầu người dùng xác thực trước khi truy cập.
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Cấu hình việc quản lý phiên bản của ứng dụng. Trong trường hợp này, việc quản lý phiên bản được đặt thành STATELESS, điều này có nghĩa là không sử dụng phiên phiên đăng nhập (session) trong việc xác thực
                .and()
                .authenticationProvider(authenticationProvider)// Cung cấp một AuthenticationProvider, được sử dụng để xác thực người dùng
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);// Thêm một bộ lọc (filter) tùy chỉnh, jwtAuthFilter, Filter này được sử dụng để xác thực thông qua JWT (JSON Web Token).
        return httpSecurity.build();
    }
}
