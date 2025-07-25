package org.example.pawtracksbe.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BulkAddPaymentsResponseDto {
    private int successCount;
    private List<PaymentErrorDetailDto> errors;
}