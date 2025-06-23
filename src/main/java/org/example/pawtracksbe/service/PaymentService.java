package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.*;

import java.util.List;

public interface PaymentService {
    List<PaymentResponseDto> getAllPayments();
    PaymentResponseDto createPayment(CreatePaymentRequestDto createPaymentRequestDto);
    PaymentResponseDto updatePayment(Long id, UpdatePaymentRequestDto updatePaymentRequestDto);
    void deletePayment(Long id);
    PaymentResponseDto getPaymentById(Long id);
    BulkAddPaymentsResponseDto addBulkPayments(List<CreatePaymentRequestDto> paymentRequests);
    List<ParsedPaymentDto> parseSheet(String sheetUrl);
}
