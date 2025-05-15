package org.example.pawtracksbe.dto;

import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
public class PaymentResponseDto {

    private Long id;

    private BigDecimal amount;

    private LocalDate date;

    private OwnerSummaryDto owner;

    private Integer visits;

    private String paymentMethod;

    private boolean pending;

    private String employee;
}