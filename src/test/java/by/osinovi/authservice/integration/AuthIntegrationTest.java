package by.osinovi.authservice.integration;

import by.osinovi.authservice.dto.auth.AuthRequest;
import by.osinovi.authservice.dto.auth.AuthResponse;
import by.osinovi.authservice.entity.AuthUser;
import by.osinovi.authservice.repository.AuthUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureWebMvc
@ActiveProfiles("test")
@Transactional
class AuthIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        authUserRepository.deleteAll();
    }

    @Test
    void fullAuthFlow_Success() throws Exception {
        // 1. Register a new user
        AuthRequest registerRequest = new AuthRequest("test@example.com", "password123");
        
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully"));

        // Verify user was created in database
        assertTrue(authUserRepository.findByEmail("test@example.com").isPresent());

        // 2. Login with the registered user
        AuthRequest loginRequest = new AuthRequest("test@example.com", "password123");
        
        String loginResponse = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn()
                .getResponse()
                .getContentAsString();

        AuthResponse authResponse = objectMapper.readValue(loginResponse, AuthResponse.class);
        assertNotNull(authResponse.getAccessToken());
        assertNotNull(authResponse.getRefreshToken());

        // 3. Validate the access token
        mockMvc.perform(get("/auth/validate-token")
                        .header("Authorization", "Bearer " + authResponse.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.username").value("test@example.com"));
    }

    @Test
    void register_DuplicateEmail() throws Exception {
        // Register first user
        AuthRequest request1 = new AuthRequest("test@example.com", "password123");
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request1)))
                .andExpect(status().isOk());

        // Try to register with same email
        AuthRequest request2 = new AuthRequest("test@example.com", "password456");
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request2)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Registration failed")));
    }

    @Test
    void login_UserNotExists() throws Exception {
        AuthRequest request = new AuthRequest("nonexistent@example.com", "password123");
        
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Authentication failed")));
    }
} 