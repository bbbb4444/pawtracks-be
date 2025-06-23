package org.example.pawtracksbe.dto;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class ParsedPaymentDto {
    private String timestamp;
    private BigDecimal earnings;
    private String method;
    private String clientName;
    private Integer visits;
    private Long matchedClientId;
}