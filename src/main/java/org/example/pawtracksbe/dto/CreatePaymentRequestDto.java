package org.example.pawtracksbe.dto;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
public class CreatePaymentRequestDto {

    @NotNull(message = "Owner ID is required")
    private Long ownerId;

    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.00", message = "Amount must be positive")
    @Digits(integer = 8, fraction = 2, message = "Amount must have up to 8 integer and 2 fractional digits")
    private BigDecimal amount;

    @NotNull(message = "Payment date is required")
    private LocalDate date;

    @NotNull(message = "Number of visits is required")
    @Min(value = 1, message = "Must have at least 1 visit")
    private Integer visits;

    @NotBlank(message = "Payment method is required")
    @Size(max = 50, message = "Payment method cannot exceed 50 characters")
    private String paymentMethod;

    @NotNull(message = "Pending status must be specified")
    private Boolean pending;

    @Size(max = 100, message = "Employee name cannot exceed 100 characters")
    private String employee;
}