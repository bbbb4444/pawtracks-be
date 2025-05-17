package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.BulkAddPaymentsResponseDto;
import org.example.pawtracksbe.dto.CreatePaymentRequestDto;
import org.example.pawtracksbe.dto.PaymentResponseDto;
import org.example.pawtracksbe.dto.UpdatePaymentRequestDto;
import org.example.pawtracksbe.entity.Owner;
import org.example.pawtracksbe.entity.Payment;
import org.example.pawtracksbe.exception.ResourceNotFoundException;
import org.example.pawtracksbe.mapper.PaymentMapper;
import org.example.pawtracksbe.repository.OwnerRepository;
import org.example.pawtracksbe.repository.PaymentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class PaymentServiceImpl implements PaymentService {
    private static final Logger log = LoggerFactory.getLogger(PaymentServiceImpl.class);

    private final PaymentRepository paymentRepository;
    private final OwnerRepository ownerRepository;
    private final PaymentMapper paymentMapper;

    @Autowired
    public PaymentServiceImpl(PaymentRepository paymentRepository,
                          OwnerRepository ownerRepository,
                          PaymentMapper paymentMapper) {
        this.paymentRepository = paymentRepository;
        this.ownerRepository = ownerRepository;
        this.paymentMapper = paymentMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public List<PaymentResponseDto> getAllPayments() {
        List<Payment> payments = paymentRepository.findAll();
        return paymentMapper.paymentsToPaymentResponseDtos(payments);
    }

    @Override
    @Transactional()
    public PaymentResponseDto createPayment(CreatePaymentRequestDto createPaymentRequestDto) {
        Payment payment = paymentMapper.createPaymentRequestDtoToPayment(createPaymentRequestDto);

        if (createPaymentRequestDto.getOwnerId() == null) {
            throw new IllegalArgumentException("Owner ID is required in the request to create a payment.");
        }

        Owner owner = ownerRepository.findById(createPaymentRequestDto.getOwnerId())
                .orElseThrow(() -> new ResourceNotFoundException("Owner not found with id: " + createPaymentRequestDto.getOwnerId()));

        payment.setOwner(owner);

        Payment savedPayment = paymentRepository.save(payment);
        return paymentMapper.paymentToPaymentResponseDto(savedPayment);
    }

    @Override
    @Transactional()
    public PaymentResponseDto updatePayment(Long id, UpdatePaymentRequestDto updatePaymentRequestDto) {
        Payment existingPayment = paymentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Payment not found"));

        paymentMapper.updatePaymentFromDto(updatePaymentRequestDto, existingPayment);

        Payment savedPayment = paymentRepository.save(existingPayment);

        return paymentMapper.paymentToPaymentResponseDto(savedPayment);
    }

    @Override
    @Transactional()
    public void deletePayment(Long id) {
        if (!paymentRepository.existsById(id)) {
            throw new ResourceNotFoundException("Payment not found");
        }
        paymentRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public PaymentResponseDto getPaymentById(Long id) {
        Payment payment = paymentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Payment not found"));
        return paymentMapper.paymentToPaymentResponseDto(payment);
    }

    @Override
    @Transactional
    public BulkAddPaymentsResponseDto addBulkPayments(List<CreatePaymentRequestDto> paymentRequests) {

        List<Payment> paymentsToSave = new ArrayList<>();

        for (int i = 0; i < paymentRequests.size(); i++) {
            CreatePaymentRequestDto paymentRequest = paymentRequests.get(i);
            log.debug("Processing payment request {}/{}: Owner ID {}", (i + 1), paymentRequests.size(), paymentRequest.getOwnerId());

            Payment payment = paymentMapper.createPaymentRequestDtoToPayment(paymentRequest);

            if (paymentRequest.getOwnerId() == null) {
                log.error("Owner ID is null for payment request at index {}", i);
                throw new IllegalArgumentException("Owner ID cannot be null for payment at index " + i + ".");
            }

            int index = i;
            Owner owner = ownerRepository.findById(paymentRequest.getOwnerId())
                    .orElseThrow(() -> {
                        log.error("Owner not found with id: {} for payment request at index {}", paymentRequest.getOwnerId(), index);
                        return new ResourceNotFoundException("Owner not found with id: " + paymentRequest.getOwnerId() + " for payment at index " + index + ".");
                    });
            payment.setOwner(owner);
            paymentsToSave.add(payment);
        }

        List<Payment> savedPayments = paymentRepository.saveAll(paymentsToSave);
        log.info("Successfully saved {} payments in a single transaction.", savedPayments.size());

        return new BulkAddPaymentsResponseDto(savedPayments.size(), new ArrayList<>());
    }
}
