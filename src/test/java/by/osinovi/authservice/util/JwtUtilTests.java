package by.osinovi.authservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Date;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTests {

    private JwtUtil jwtUtil;
    private SecretKey secretKey;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        secretKey = Keys.hmacShaKeyFor("secret-key-secret-key-secret-key-secret-key".getBytes());
        jwtUtil = new JwtUtil("secret-key-secret-key-secret-key-secret-key");

        setField(jwtUtil, "accessTokenExpiration", 3600L);
        setField(jwtUtil, "refreshTokenExpiration", 86400L);

        userDetails = User.withUsername("test@example.com")
                .password("password")
                .authorities("USER")
                .build();
    }

    private void setField(Object target, String fieldName, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    @Test
    void generateAccessToken_ValidUserDetails_ReturnsValidToken() {
        String token = jwtUtil.generateAccessToken(userDetails);

        assertNotNull(token);
        assertEquals("test@example.com", jwtUtil.extractEmail(token));
        assertEquals("access_token", extractClaim(token, Claims::getSubject));
        assertFalse(jwtUtil.isTokenExpired(token));
        assertTrue(jwtUtil.isTokenValid(token, userDetails));
    }

    @Test
    void generateRefreshToken_ValidUserDetails_ReturnsValidRefreshToken() {
        String token = jwtUtil.generateRefreshToken(userDetails);

        assertNotNull(token);
        assertEquals("test@example.com", jwtUtil.extractEmail(token));
        assertTrue(jwtUtil.isRefreshToken(token));
        assertFalse(jwtUtil.isTokenExpired(token));
        assertTrue(jwtUtil.isTokenValid(token, userDetails));
    }

    @Test
    void isTokenValid_WrongUserDetails_ReturnsFalse() {
        String token = jwtUtil.generateAccessToken(userDetails);
        UserDetails wrongUser = User.withUsername("wrong@example.com")
                .password("password")
                .authorities("USER")
                .build();

        boolean isValid = jwtUtil.isTokenValid(token, wrongUser);

        assertFalse(isValid);
    }

    @Test
    void isTokenValid_ExpiredToken_ReturnsFalse() throws NoSuchFieldException, IllegalAccessException {
        setField(jwtUtil, "accessTokenExpiration", -1L); // Принудительное истечение срока
        String token = jwtUtil.generateAccessToken(userDetails);

        boolean isValid = jwtUtil.isTokenValid(token, userDetails);

        assertFalse(isValid);
        assertTrue(jwtUtil.isTokenExpired(token));
    }

    @Test
    void isTokenValid_MalformedToken_ReturnsFalse() {
        String malformedToken = "invalid.token.here";

        boolean isValid = jwtUtil.isTokenValid(malformedToken, userDetails);

        assertFalse(isValid);
    }

    @Test
    void isTokenValid_InvalidSignature_ReturnsFalse() {
        SecretKey wrongKey = Keys.hmacShaKeyFor("wrong-key-wrong-key-wrong-key-wrong-key".getBytes());
        String invalidToken = Jwts.builder()
                .subject("access_token")
                .claim("email", "test@example.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(wrongKey)
                .compact();

        boolean isValid = jwtUtil.isTokenValid(invalidToken, userDetails);

        assertFalse(isValid);
    }

    @Test
    void extractEmail_ValidToken_ReturnsCorrectEmail() {
        String token = jwtUtil.generateAccessToken(userDetails);

        String email = jwtUtil.extractEmail(token);

        assertEquals("test@example.com", email);
    }

    @Test
    void extractEmail_MalformedToken_ThrowsJwtException() {
        String malformedToken = "invalid.token.here";

        assertThrows(JwtException.class, () -> jwtUtil.extractEmail(malformedToken));
    }

    @Test
    void isRefreshToken_AccessToken_ReturnsFalse() {
        String token = jwtUtil.generateAccessToken(userDetails);

        boolean isRefresh = jwtUtil.isRefreshToken(token);

        assertFalse(isRefresh);
    }

    @Test
    void isRefreshToken_RefreshToken_ReturnsTrue() {
        String token = jwtUtil.generateRefreshToken(userDetails);

        boolean isRefresh = jwtUtil.isRefreshToken(token);

        assertTrue(isRefresh);
    }

    @Test
    void isTokenExpired_ValidToken_ReturnsFalse() {
        String token = jwtUtil.generateAccessToken(userDetails);

        boolean isExpired = jwtUtil.isTokenExpired(token);

        assertFalse(isExpired);
    }

    @Test
    void isTokenExpired_ExpiredToken_ReturnsTrue() throws NoSuchFieldException, IllegalAccessException {
        setField(jwtUtil, "accessTokenExpiration", -1L);
        String token = jwtUtil.generateAccessToken(userDetails);

        boolean isExpired = jwtUtil.isTokenExpired(token);

        assertTrue(isExpired);
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
        return resolver.apply(claims);
    }
}