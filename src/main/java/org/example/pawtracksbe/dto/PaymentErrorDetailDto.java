package org.example.pawtracksbe.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PaymentErrorDetailDto {
    private CreatePaymentRequestDto paymentData;
    private String error;
}