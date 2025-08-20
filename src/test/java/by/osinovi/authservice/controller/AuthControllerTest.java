package by.osinovi.authservice.controller;

import by.osinovi.authservice.dto.auth.AuthRequest;
import by.osinovi.authservice.dto.auth.AuthResponse;
import by.osinovi.authservice.service.AuthService;
import by.osinovi.authservice.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtUtil jwtUtil;

    @Autowired
    private ObjectMapper objectMapper;

    private AuthRequest validAuthRequest;
    private AuthResponse authResponse;

    @BeforeEach
    void setUp() {
        validAuthRequest = new AuthRequest();
        validAuthRequest.setEmail("test@example.com");
        validAuthRequest.setPassword("password123");

        authResponse = new AuthResponse();
        authResponse.setAccessToken("accessToken");
        authResponse.setRefreshToken("refreshToken");
    }

    @Test
    void login_Success() throws Exception {
        when(authService.login(any(AuthRequest.class))).thenReturn(authResponse);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.refreshToken").value("refreshToken"));
    }

    @Test
    void login_InvalidRequest() throws Exception {
        AuthRequest invalidRequest = new AuthRequest();
        invalidRequest.setEmail("invalid-email");
        invalidRequest.setPassword("123"); // Too short

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_AuthenticationFailed() throws Exception {
        when(authService.login(any(AuthRequest.class)))
                .thenThrow(new RuntimeException("Authentication failed"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Authentication failed")));
    }

    @Test
    void refreshToken_Success() throws Exception {
        when(authService.refresh(anyString())).thenReturn(authResponse);

        mockMvc.perform(post("/auth/refresh-token")
                        .header("Authorization", "Bearer refreshToken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.refreshToken").value("refreshToken"));
    }

    @Test
    void refreshToken_NoAuthorizationHeader() throws Exception {
        mockMvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshToken_InvalidToken() throws Exception {
        when(authService.refresh(anyString()))
                .thenThrow(new RuntimeException("Invalid refresh token"));

        mockMvc.perform(post("/auth/refresh-token")
                        .header("Authorization", "Bearer invalidToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Error processing refresh token")));
    }

    @Test
    void validateToken_Success() throws Exception {
        when(authService.validate(anyString())).thenReturn(true);
        when(authService.getTokenFromHeader(anyString())).thenReturn("validToken");
        when(jwtUtil.extractEmail("validToken")).thenReturn("test@example.com");

        mockMvc.perform(get("/auth/validate-token")
                        .header("Authorization", "Bearer validToken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.username").value("test@example.com"));
    }

    @Test
    void validateToken_InvalidToken() throws Exception {
        when(authService.validate(anyString())).thenReturn(false);
        when(authService.getTokenFromHeader(anyString())).thenReturn("invalidToken");
        when(jwtUtil.extractEmail("invalidToken")).thenReturn("test@example.com");

        mockMvc.perform(get("/auth/validate-token")
                        .header("Authorization", "Bearer invalidToken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.username").value("test@example.com"));
    }

    @Test
    void validateToken_NoAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/auth/validate-token"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateToken_Exception() throws Exception {
        when(authService.validate(anyString()))
                .thenThrow(new RuntimeException("Invalid token format"));

        mockMvc.perform(get("/auth/validate-token")
                        .header("Authorization", "Bearer malformedToken"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Invalid token")));
    }

    @Test
    void register_Success() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully"));
    }

    @Test
    void register_InvalidRequest() throws Exception {
        AuthRequest invalidRequest = new AuthRequest();
        invalidRequest.setEmail("invalid-email");
        invalidRequest.setPassword("123"); // Too short

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_RegistrationFailed() throws Exception {
        doThrow(new RuntimeException("Email already exists"))
                .when(authService).register(any(AuthRequest.class));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Registration failed")));
    }
} 