package by.osinovi.authservice.config;

import by.osinovi.authservice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private static final String TOKEN = "test-jwt-token";
    private static final String EMAIL = "test@example.com";
    private static final String BEARER_TOKEN = "Bearer " + TOKEN;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void testValidJwtToken() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(BEARER_TOKEN);
        when(jwtUtil.isTokenValid(TOKEN, null)).thenReturn(true);
        when(jwtUtil.extractEmail(TOKEN)).thenReturn(EMAIL);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(jwtUtil).isTokenValid(TOKEN, null);
        verify(jwtUtil).extractEmail(TOKEN);
        verify(filterChain).doFilter(request, response);
        verify(request).getHeader("Authorization");
    }

    @Test
    void testInvalidJwtToken() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(BEARER_TOKEN);
        when(jwtUtil.isTokenValid(TOKEN, null)).thenThrow(new RuntimeException("Invalid token"));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(jwtUtil).isTokenValid(TOKEN, null);
        verify(filterChain).doFilter(request, response);
        verifyNoMoreInteractions(jwtUtil);
    }

    @Test
    void testNoAuthorizationHeader() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void testInvalidBearerToken() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Invalid " + TOKEN);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtUtil);
    }
}