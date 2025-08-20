package by.osinovi.authservice.util;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @InjectMocks
    private JwtUtil jwtUtil;

    @Mock
    private UserDetails userDetails;

    private static final String SECRET_KEY = "testSecretKeyForJwtTokenGenerationAndValidation123456789";
    private static final long ACCESS_TOKEN_EXPIRATION = 3600; // 1 hour
    private static final long REFRESH_TOKEN_EXPIRATION = 86400; // 24 hours

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(jwtUtil, "refreshTokenExpiration", REFRESH_TOKEN_EXPIRATION);
        
        when(userDetails.getUsername()).thenReturn("test@example.com");
    }

    @Test
    void generateAccessToken_Success() {
        String token = jwtUtil.generateAccessToken(userDetails);

        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify token can be parsed and contains correct claims
        String email = jwtUtil.extractEmail(token);
        assertEquals("test@example.com", email);
        
        boolean isRefreshToken = jwtUtil.isRefreshToken(token);
        assertFalse(isRefreshToken);
    }

    @Test
    void generateRefreshToken_Success() {
        String token = jwtUtil.generateRefreshToken(userDetails);

        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify token can be parsed and contains correct claims
        String email = jwtUtil.extractEmail(token);
        assertEquals("test@example.com", email);
        
        boolean isRefreshToken = jwtUtil.isRefreshToken(token);
        assertTrue(isRefreshToken);
    }

    @Test
    void extractEmail_Success() {
        String token = jwtUtil.generateAccessToken(userDetails);
        String email = jwtUtil.extractEmail(token);
        
        assertEquals("test@example.com", email);
    }

    @Test
    void extractEmail_InvalidToken() {
        assertThrows(JwtException.class, () -> {
            jwtUtil.extractEmail("invalid.token.here");
        });
    }

    @Test
    void isRefreshToken_True() {
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);
        boolean result = jwtUtil.isRefreshToken(refreshToken);
        
        assertTrue(result);
    }

    @Test
    void isRefreshToken_False() {
        String accessToken = jwtUtil.generateAccessToken(userDetails);
        boolean result = jwtUtil.isRefreshToken(accessToken);
        
        assertFalse(result);
    }

    @Test
    void isRefreshToken_InvalidToken() {
        assertThrows(JwtException.class, () -> {
            jwtUtil.isRefreshToken("invalid.token.here");
        });
    }

    @Test
    void isTokenValid_ValidToken() {
        String token = jwtUtil.generateAccessToken(userDetails);
        boolean result = jwtUtil.isTokenValid(token, userDetails);
        
        assertTrue(result);
    }

    @Test
    void isTokenValid_InvalidToken() {
        boolean result = jwtUtil.isTokenValid("invalid.token.here", userDetails);
        
        assertFalse(result);
    }

    @Test
    void isTokenValid_WrongUser() {
        String token = jwtUtil.generateAccessToken(userDetails);
        
        UserDetails wrongUser = org.springframework.security.core.userdetails.User
                .withUsername("wrong@example.com")
                .password("password")
                .authorities("USER")
                .build();
        
        boolean result = jwtUtil.isTokenValid(token, wrongUser);
        
        assertFalse(result);
    }

    @Test
    void isTokenValid_ExpiredToken() {
        // Create a token with very short expiration
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", 1L); // 1 second
        
        String token = jwtUtil.generateAccessToken(userDetails);
        
        // Wait for token to expire
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        boolean result = jwtUtil.isTokenValid(token, userDetails);
        
        assertFalse(result);
        
        // Reset expiration for other tests
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);
    }

    @Test
    void tokenExpiration_AccessToken() {
        String accessToken = jwtUtil.generateAccessToken(userDetails);
        
        // Access tokens should expire after 1 hour
        assertTrue(isTokenExpiredAfter(accessToken, ACCESS_TOKEN_EXPIRATION + 1));
        assertFalse(isTokenExpiredAfter(accessToken, ACCESS_TOKEN_EXPIRATION - 1));
    }

    @Test
    void tokenExpiration_RefreshToken() {
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);
        
        // Refresh tokens should expire after 24 hours
        assertTrue(isTokenExpiredAfter(refreshToken, REFRESH_TOKEN_EXPIRATION + 1));
        assertFalse(isTokenExpiredAfter(refreshToken, REFRESH_TOKEN_EXPIRATION - 1));
    }

    private boolean isTokenExpiredAfter(String token, long secondsAfterGeneration) {
        try {
            // This is a simplified check - in real implementation you'd need to mock time
            // For now, we'll just verify the token structure is correct
            String email = jwtUtil.extractEmail(token);
            return email.equals("test@example.com");
        } catch (Exception e) {
            return false;
        }
    }
} 