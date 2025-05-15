package org.example.pawtracksbe.dto;

import lombok.Data;
import org.example.pawtracksbe.types.PaymentMethod;

import java.math.BigDecimal;
import java.util.List;

/**
 * A summary DTO containing specific Owner details needed for Payment responses.
 */
@Data
public class OwnerSummaryDto {
    private Long id;
    private String firstName;
    private String lastName;
    private List<String> pets;
    private BigDecimal price15;
    private BigDecimal price30;
    private BigDecimal price60;
    private PaymentMethod preferredPaymentMethod;
}