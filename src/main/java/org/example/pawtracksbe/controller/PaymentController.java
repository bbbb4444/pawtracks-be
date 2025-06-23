package org.example.pawtracksbe.controller;

import jakarta.validation.Valid;
import org.example.pawtracksbe.dto.*;
import org.example.pawtracksbe.service.PaymentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/payments")
public class PaymentController {

    private final PaymentService paymentService;

    @Autowired
    public PaymentController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @GetMapping
    public ResponseEntity<List<PaymentResponseDto>> getAllPayments() {
        List<PaymentResponseDto> payments = paymentService.getAllPayments();
        return ResponseEntity.ok(payments);
    }

    @GetMapping("/{id}")
    public ResponseEntity<PaymentResponseDto> getPaymentById(@PathVariable Long id) {
        PaymentResponseDto payment = paymentService.getPaymentById(id);
        return ResponseEntity.ok(payment);
    }

    @PostMapping
    public ResponseEntity<PaymentResponseDto> createPayment(@Valid @RequestBody CreatePaymentRequestDto createPaymentRequestDto) {
        PaymentResponseDto createdPayment = paymentService.createPayment(createPaymentRequestDto);
        return new ResponseEntity<>(createdPayment, HttpStatus.CREATED);

    }

    @PutMapping("/{id}")
    public ResponseEntity<PaymentResponseDto> updatePayment(
            @PathVariable Long id,
            @Valid @RequestBody UpdatePaymentRequestDto updatePaymentRequestDto) {
        PaymentResponseDto updatedPayment = paymentService.updatePayment(id, updatePaymentRequestDto);
        return ResponseEntity.ok(updatedPayment);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePayment(@PathVariable Long id) {
        paymentService.deletePayment(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/bulk")
    public ResponseEntity<BulkAddPaymentsResponseDto> addBulkPayments(@Valid @RequestBody List<CreatePaymentRequestDto> paymentRequests) {
        BulkAddPaymentsResponseDto response = paymentService.addBulkPayments(paymentRequests);
        if (!response.getErrors().isEmpty() && response.getSuccessCount() == 0) {
            return ResponseEntity.badRequest().body(response);
        }
        if (!response.getErrors().isEmpty()) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/parse-sheet")
    public ResponseEntity<List<ParsedPaymentDto>> parseSheet(@Valid @RequestBody ParseSheetRequestDto request) {
        List<ParsedPaymentDto> parsedPayments = paymentService.parseSheet(request.getSheetUrl());
        return ResponseEntity.ok(parsedPayments);
    }
}