package by.osinovi.authservice.dto.user;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserRequest {
    @NotBlank(message = "Name is required")
    @Size(max = 32, message = "Name must not exceed 64 characters")
    private String name;

    @NotBlank(message = "Surname is required")
    @Size(max = 32, message = "Surname must not exceed 64 characters")
    private String surname;

    private LocalDate birthDate;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    @Size(max = 128, message = "Email must not exceed 128 characters")
    private String email;
}