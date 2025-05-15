package org.example.pawtracksbe.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.example.pawtracksbe.types.PaymentMethod;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "owners")
public class Owner {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "First name is mandatory")
    @Size(max = 100, message = "First name must be less than 100 characters")
    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @NotBlank(message = "First name is mandatory")
    @Size(max = 100, message = "Last name cannot exceed 100 characters")
    @Column(name = "last_name", nullable = false)
    private String lastName;

    @NotNull()
    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "pets")
    @Size(max = 50, message = "Maximum of 50 pets allowed")
    private List<String> pets = new ArrayList<>();

    @NotNull(message = "Price for 15 minutes is required")
    @DecimalMin(value = "0.00", message = "Price for 15 minutes cannot be negative")
    @Digits(integer = 6, fraction = 2, message = "Price for 15 minutes must have up to 6 integer and 2 fractional digits")
    @Column(name = "price_15")
    private BigDecimal price15;

    @NotNull(message = "Price for 30 minutes is required")
    @DecimalMin(value = "0.00", message = "Price for 30 minutes cannot be negative")
    @Digits(integer = 6, fraction = 2, message = "Price for 30 minutes must have up to 6 integer and 2 fractional digits")
    @Column(name = "price_30")
    private BigDecimal price30;

    @NotNull(message = "Price for 60 minutes is required")
    @DecimalMin(value = "0.00", message = "Price for 60 minutes cannot be negative")
    @Digits(integer = 6, fraction = 2, message = "Price for 60 minutes must have up to 6 integer and 2 fractional digits")
    @Column(name = "price_60")
    private BigDecimal price60;

    @NotNull(message = "Preferred payment method must be specified")
    @Enumerated(EnumType.STRING)
    @Column(name = "preferred_payment_method", nullable = false, length = 50)
    private PaymentMethod preferredPaymentMethod;

}
