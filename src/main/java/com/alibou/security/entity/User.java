package com.alibou.security.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@ToString
@Table(name = "_user")
public class User implements UserDetails {
    @Id
    @GeneratedValue
    private Integer id;
    private String fullName;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    // Tài khoản người dùng có còn hiệu lực không?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // Tài khoản người dùng có bị khóa (locked) hay không?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // Thông tin xác thực của người dùng có còn hiệu lực không?
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // Tài khoản người dùng có được kích hoạt (enabled) hay không?
    @Override
    public boolean isEnabled() {
        return true;
    }
}
