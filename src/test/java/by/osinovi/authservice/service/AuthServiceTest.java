package by.osinovi.authservice.service;

import by.osinovi.authservice.dto.auth.AuthRequest;
import by.osinovi.authservice.dto.auth.AuthResponse;
import by.osinovi.authservice.entity.AuthUser;
import by.osinovi.authservice.repository.AuthUserRepository;
import by.osinovi.authservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    private AuthUser testUser;
    private AuthRequest authRequest;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        testUser = new AuthUser();
        testUser.setId(1L);
        testUser.setEmail("test@example.com");
        testUser.setPassword("encodedPassword");

        authRequest = new AuthRequest();
        authRequest.setEmail("test@example.com");
        authRequest.setPassword("password123");

        userDetails = org.springframework.security.core.userdetails.User
                .withUsername("test@example.com")
                .password("encodedPassword")
                .authorities("USER")
                .build();
    }

    @Test
    void loadUserByUsername_Success() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        UserDetails result = authService.loadUserByUsername("test@example.com");

        assertNotNull(result);
        assertEquals("test@example.com", result.getUsername());
        assertEquals("encodedPassword", result.getPassword());
        assertTrue(result.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("USER")));
    }

    @Test
    void loadUserByUsername_UserNotFound() {
        when(authUserRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> {
            authService.loadUserByUsername("nonexistent@example.com");
        });
    }

    @Test
    void register_Success() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

        assertDoesNotThrow(() -> authService.register(authRequest));

        verify(authUserRepository).findByEmail("test@example.com");
        verify(passwordEncoder).encode("password123");
        verify(authUserRepository).save(any(AuthUser.class));
    }

    @Test
    void register_EmailAlreadyExists() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.register(authRequest);
        });

        assertEquals("Email already exists", exception.getMessage());
        verify(authUserRepository, never()).save(any(AuthUser.class));
    }

    @Test
    void login_Success() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "encodedPassword")).thenReturn(true);
        when(jwtUtil.generateAccessToken(any(UserDetails.class))).thenReturn("accessToken");
        when(jwtUtil.generateRefreshToken(any(UserDetails.class))).thenReturn("refreshToken");

        AuthResponse result = authService.login(authRequest);

        assertNotNull(result);
        assertEquals("accessToken", result.getAccessToken());
        assertEquals("refreshToken", result.getRefreshToken());
    }

    @Test
    void login_UserNotFound() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> {
            authService.login(authRequest);
        });
    }

    @Test
    void login_WrongPassword() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "encodedPassword")).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> {
            authService.login(authRequest);
        });
    }

    @Test
    void refresh_Success() {
        String refreshToken = "refreshToken";
        when(jwtUtil.isRefreshToken(refreshToken)).thenReturn(true);
        when(jwtUtil.extractEmail(refreshToken)).thenReturn("test@example.com");
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtUtil.generateAccessToken(any(UserDetails.class))).thenReturn("newAccessToken");
        when(jwtUtil.generateRefreshToken(any(UserDetails.class))).thenReturn("newRefreshToken");

        AuthResponse result = authService.refresh("Bearer " + refreshToken);

        assertNotNull(result);
        assertEquals("newAccessToken", result.getAccessToken());
        assertEquals("newRefreshToken", result.getRefreshToken());
    }

    @Test
    void refresh_InvalidTokenType() {
        String accessToken = "accessToken";
        when(jwtUtil.isRefreshToken(accessToken)).thenReturn(false);

        assertThrows(JwtException.class, () -> {
            authService.refresh("Bearer " + accessToken);
        });
    }

    @Test
    void validate_Success() {
        String token = "validToken";
        when(jwtUtil.extractEmail(token)).thenReturn("test@example.com");
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtUtil.isTokenValid(token, any(UserDetails.class))).thenReturn(true);

        boolean result = authService.validate("Bearer " + token);

        assertTrue(result);
    }

    @Test
    void validate_InvalidToken() {
        String token = "invalidToken";
        when(jwtUtil.extractEmail(token)).thenReturn("test@example.com");
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtUtil.isTokenValid(token, any(UserDetails.class))).thenReturn(false);

        boolean result = authService.validate("Bearer " + token);

        assertFalse(result);
    }

    @Test
    void getTokenFromHeader_Success() {
        String result = authService.getTokenFromHeader("Bearer token123");
        assertEquals("token123", result);
    }

    @Test
    void getTokenFromHeader_InvalidHeader() {
        assertThrows(JwtException.class, () -> {
            authService.getTokenFromHeader("Invalid token123");
        });
    }

    @Test
    void getTokenFromHeader_NullHeader() {
        assertThrows(JwtException.class, () -> {
            authService.getTokenFromHeader(null);
        });
    }
} 