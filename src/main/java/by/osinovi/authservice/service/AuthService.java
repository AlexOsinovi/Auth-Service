package by.osinovi.authservice.service;

import by.osinovi.authservice.dto.auth.AuthRequest;
import by.osinovi.authservice.dto.auth.AuthResponse;
import by.osinovi.authservice.entity.AuthUser;
import by.osinovi.authservice.repository.AuthUserRepository;
import by.osinovi.authservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = authUserRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));
        return User.withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities("USER")
                .build();
    }

    @Transactional
    public void register(AuthRequest request) {
        if (authUserRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        }

        AuthUser authUser = new AuthUser();
        authUser.setEmail(request.getEmail());
        authUser.setPassword(passwordEncoder.encode(request.getPassword()));
        authUserRepository.save(authUser);
    }

    public AuthResponse login(AuthRequest authRequest) {
        AuthUser user = authUserRepository.findByEmail(authRequest.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(authRequest.getPassword(), user.getPassword()))
            throw new BadCredentialsException("Wrong password");

        UserDetails userDetails = loadUserByUsername(authRequest.getEmail());
        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse refresh(String tokenHeader) {
        String token = getTokenFromHeader(tokenHeader);
        if (!jwtUtil.isRefreshToken(token)) throw new JwtException("Invalid token type");
        String email = jwtUtil.extractEmail(token);
        UserDetails userDetails = loadUserByUsername(email);
        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);
        return new AuthResponse(accessToken, refreshToken);
    }

    public boolean validate(String tokenHeader) {
        String token = getTokenFromHeader(tokenHeader);
        String email = jwtUtil.extractEmail(token);
        UserDetails userDetails = loadUserByUsername(email);
        return jwtUtil.isTokenValid(token, userDetails);
    }

    public String getTokenFromHeader(String header) {
        if (header != null && header.startsWith("Bearer ")) return header.substring(7);
        else throw new JwtException("Invalid <Authorization> header type");
    }
}