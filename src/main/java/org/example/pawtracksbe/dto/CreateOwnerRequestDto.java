package org.example.pawtracksbe.dto;

import jakarta.validation.constraints.*;
import lombok.Data;
import org.example.pawtracksbe.types.PaymentMethod;

import java.math.BigDecimal;
import java.util.List;

@Data
public class CreateOwnerRequestDto {

    @NotBlank(message = "First name is mandatory")
    @Size(max = 100, message = "First name must be less than 100 characters")
    private String firstName;

    @NotBlank(message = "Last name is mandatory")
    @Size(max = 100, message = "Last name must be less than 100 characters")
    private String lastName;

    @Size(max = 50, message = "Maximum of 50 pets allowed")
    private List<String> pets;

    @NotNull(message = "Price for 15 minutes is required")
    @DecimalMin(value = "0.00", message = "Price for 15 minutes cannot be negative")
    @Digits(integer = 6, fraction = 2, message = "Price for 15 minutes is invalid")
    private BigDecimal price15;

    @NotNull(message = "Price for 30 minutes is required")
    @DecimalMin(value = "0.00", message = "Price for 30 minutes cannot be negative")
    @Digits(integer = 6, fraction = 2, message = "Price for 30 minutes is invalid")
    private BigDecimal price30;

    @NotNull(message = "Price for 60 minutes is required")
    @DecimalMin(value = "0.00", message = "Price for 60 minutes cannot be negative")
    @Digits(integer = 6, fraction = 2, message = "Price for 60 minutes is invalid")
    private BigDecimal price60;

    @NotNull(message = "Preferred payment method must be specified")
    private PaymentMethod preferredPaymentMethod;
}