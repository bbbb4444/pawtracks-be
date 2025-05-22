package org.example.pawtracksbe.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotNull(message = "App user cannot be null")
    @ManyToOne
    @JoinColumn(nullable = false, name = "user_id")
    private AppUser user;

    @NotBlank(message = "Token cannot be blank")
    @Column(nullable = false, unique = true)
    private String token;

    @NotNull(message = "expiryDate cannot be dull")
    @Column(nullable = false)
    private Instant expiryDate;
}