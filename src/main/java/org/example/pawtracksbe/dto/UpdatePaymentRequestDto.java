package org.example.pawtracksbe.dto;

import jakarta.validation.constraints.*; // Keep specific field validations if a value IS provided
import lombok.Data;
import lombok.NoArgsConstructor; // Useful for DTOs
import lombok.AllArgsConstructor; // Useful for DTOs

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdatePaymentRequestDto {
    private Long ownerId;

    @DecimalMin(value = "0.00", message = "Amount must be positive")
    @Digits(integer = 8, fraction = 2, message = "Amount must have up to 8 integer and 2 fractional digits")
    private BigDecimal amount;

    private LocalDate date;

    @Min(value = 1, message = "Must have at least 1 visit")
    private Integer visits;

    @Size(max = 50, message = "Payment method cannot exceed 50 characters")
    private String paymentMethod;

    private Boolean pending;

    @Size(max = 100, message = "Employee name cannot exceed 100 characters")
    private String employee;
}