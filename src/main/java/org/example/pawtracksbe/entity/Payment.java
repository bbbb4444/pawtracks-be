package org.example.pawtracksbe.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "payments")
public class Payment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @DecimalMin(value = "0.00", message = "Amount cannot be negative")
    @Digits(integer = 8, fraction = 2, message = "Price for 15 minutes must have up to 6 integer and 2 fractional digits")
    @Column(name = "amount", nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;

    @NotNull(message = "Payment date is required")
    @Column(name = "payment_date", nullable = false)
    private LocalDate date;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = true)
    private Owner owner;

    @Column(name = "visits", nullable = true)
    private Integer visits;

    @NotBlank(message = "Payment method is required")
    @Size(max = 50, message = "Payment method cannot exceed 50 characters")
    @Column(name = "payment_method", length = 50, nullable = false)
    private String paymentMethod;

    @Column(name = "is_pending", nullable = false)
    private boolean pending;

    @Size(max = 100, message = "Employee name cannot exceed 100 characters")
    @Column(name = "employee", length = 100)
    private String employee;
}
