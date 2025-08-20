package by.osinovi.authservice.service;

import by.osinovi.authservice.dto.auth.AuthRequest;
import by.osinovi.authservice.dto.auth.AuthResponse;
import by.osinovi.authservice.entity.AuthUser;
import by.osinovi.authservice.repository.AuthUserRepository;
import by.osinovi.authservice.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import io.jsonwebtoken.JwtException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTests {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    private AuthUser authUser;
    private AuthRequest authRequest;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        authUser = new AuthUser(1L, "test@example.com", "encodedPassword");
        authRequest = new AuthRequest("test@example.com", "password");
        userDetails = User.withUsername("test@example.com")
                .password("encodedPassword")
                .authorities("USER")
                .build();
    }

    @Test
    void loadUserByUsername_UserExists_ReturnsUserDetails() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(authUser));

        UserDetails result = authService.loadUserByUsername("test@example.com");

        assertNotNull(result);
        assertEquals("test@example.com", result.getUsername());
        assertEquals("encodedPassword", result.getPassword());
        assertTrue(result.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("USER")));
    }

    @Test
    void loadUserByUsername_UserNotFound_ThrowsUsernameNotFoundException() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> authService.loadUserByUsername("test@example.com"));
    }

    @Test
    void register_NewUser_SuccessfullyRegisters() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password")).thenReturn("encodedPassword");
        when(authUserRepository.save(any(AuthUser.class))).thenReturn(authUser);

        authService.register(authRequest);

        verify(authUserRepository).save(any(AuthUser.class));
        verify(passwordEncoder).encode("password");
    }

    @Test
    void register_EmailExists_ThrowsIllegalArgumentException() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(authUser));

        assertThrows(IllegalArgumentException.class, () -> authService.register(authRequest));
        verify(authUserRepository, never()).save(any());
    }

    @Test
    void login_ValidCredentials_ReturnsAuthResponse() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(authUser));
        when(passwordEncoder.matches("password", "encodedPassword")).thenReturn(true);
        when(jwtUtil.generateAccessToken(any(UserDetails.class))).thenReturn("accessToken");
        when(jwtUtil.generateRefreshToken(any(UserDetails.class))).thenReturn("refreshToken");

        AuthResponse response = authService.login(authRequest);

        assertNotNull(response);
        assertEquals("accessToken", response.getAccessToken());
        assertEquals("refreshToken", response.getRefreshToken());
    }

    @Test
    void login_InvalidCredentials_ThrowsBadCredentialsException() {
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(authUser));
        when(passwordEncoder.matches("password", "encodedPassword")).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> authService.login(authRequest));
    }

    @Test
    void refresh_ValidRefreshToken_ReturnsAuthResponse() {
        String tokenHeader = "Bearer refreshToken";
        when(jwtUtil.isRefreshToken("refreshToken")).thenReturn(true);
        when(jwtUtil.extractEmail("refreshToken")).thenReturn("test@example.com");
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(authUser));
        when(jwtUtil.generateAccessToken(any(UserDetails.class))).thenReturn("newAccessToken");
        when(jwtUtil.generateRefreshToken(any(UserDetails.class))).thenReturn("newRefreshToken");

        AuthResponse response = authService.refresh(tokenHeader);

        assertNotNull(response);
        assertEquals("newAccessToken", response.getAccessToken());
        assertEquals("newRefreshToken", response.getRefreshToken());
    }

    @Test
    void refresh_InvalidToken_ThrowsJwtException() {
        String tokenHeader = "Bearer invalidToken";
        when(jwtUtil.isRefreshToken("invalidToken")).thenReturn(false);

        assertThrows(JwtException.class, () -> authService.refresh(tokenHeader));
    }


    @Test
    void validate_ValidToken_ReturnsTrue() {
        String tokenHeader = "Bearer validToken";
        when(jwtUtil.extractEmail(eq("validToken"))).thenReturn("test@example.com");
        when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(authUser));
        when(jwtUtil.isTokenValid(eq("validToken"), any(UserDetails.class))).thenReturn(true);

        boolean result = authService.validate(tokenHeader);

        assertTrue(result);
    }

    @Test
    void getTokenFromHeader_ValidHeader_ReturnsToken() {
        String tokenHeader = "Bearer validToken";

        String result = authService.getTokenFromHeader(tokenHeader);

        assertEquals("validToken", result);
    }

    @Test
    void getTokenFromHeader_InvalidHeader_ThrowsJwtException() {
        String tokenHeader = "InvalidHeader";

        assertThrows(JwtException.class, () -> authService.getTokenFromHeader(tokenHeader));
    }
}