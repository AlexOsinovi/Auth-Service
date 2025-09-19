package by.osinovi.authservice.repository;

import by.osinovi.authservice.entity.AuthUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


@DataJpaTest
class AuthUserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AuthUserRepository authUserRepository;

    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        testUser = new AuthUser();
        testUser.setEmail("test@example.com");
        testUser.setPassword("encodedPassword");
    }

    @Test
    void findByEmail_UserExists() {
        entityManager.persistAndFlush(testUser);

        Optional<AuthUser> found = authUserRepository.findByEmail("test@example.com");

        assertTrue(found.isPresent());
        assertEquals("test@example.com", found.get().getEmail());
        assertEquals("encodedPassword", found.get().getPassword());
    }

    @Test
    void findByEmail_UserNotExists() {
        Optional<AuthUser> found = authUserRepository.findByEmail("nonexistent@example.com");

        assertFalse(found.isPresent());
    }

    @Test
    void existsByEmail_UserExists() {
        entityManager.persistAndFlush(testUser);

        boolean exists = authUserRepository.existsByEmail("test@example.com");

        assertTrue(exists);
    }

    @Test
    void existsByEmail_UserNotExists() {
        boolean exists = authUserRepository.existsByEmail("nonexistent@example.com");

        assertFalse(exists);
    }

    @Test
    void save_NewUser() {
        AuthUser saved = authUserRepository.save(testUser);

        assertNotNull(saved.getId());
        assertEquals("test@example.com", saved.getEmail());
        assertEquals("encodedPassword", saved.getPassword());
    }

    @Test
    void save_UpdateExistingUser() {
        AuthUser saved = entityManager.persistAndFlush(testUser);
        saved.setPassword("newEncodedPassword");

        AuthUser updated = authUserRepository.save(saved);

        assertEquals(saved.getId(), updated.getId());
        assertEquals("test@example.com", updated.getEmail());
        assertEquals("newEncodedPassword", updated.getPassword());
    }

    @Test
    void findById_UserExists() {
        AuthUser saved = entityManager.persistAndFlush(testUser);

        Optional<AuthUser> found = authUserRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertEquals(saved.getId(), found.get().getId());
        assertEquals("test@example.com", found.get().getEmail());
    }

    @Test
    void findById_UserNotExists() {
        Optional<AuthUser> found = authUserRepository.findById(999L);

        assertFalse(found.isPresent());
    }

    @Test
    void delete_UserExists() {
        AuthUser saved = entityManager.persistAndFlush(testUser);

        authUserRepository.deleteById(saved.getId());

        Optional<AuthUser> found = authUserRepository.findById(saved.getId());
        assertFalse(found.isPresent());
    }
} 