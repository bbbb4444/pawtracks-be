package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.BulkAddPaymentsResponseDto;
import org.example.pawtracksbe.dto.CreatePaymentRequestDto;
import org.example.pawtracksbe.dto.PaymentResponseDto;

import java.util.List;

public interface PaymentService {
    List<PaymentResponseDto> getAllPayments();
    PaymentResponseDto createPayment(CreatePaymentRequestDto createPaymentRequestDto);
    PaymentResponseDto updatePayment(Long id, CreatePaymentRequestDto updatePaymentRequestDto);
    void deletePayment(Long id);
    PaymentResponseDto getPaymentById(Long id);
    BulkAddPaymentsResponseDto addBulkPayments(List<CreatePaymentRequestDto> paymentRequests);
}
