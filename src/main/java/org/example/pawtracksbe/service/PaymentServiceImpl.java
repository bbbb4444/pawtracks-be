package org.example.pawtracksbe.service;

import com.google.api.services.sheets.v4.Sheets;
import com.google.api.services.sheets.v4.model.ValueRange;
import org.example.pawtracksbe.dto.*;
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
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class PaymentServiceImpl implements PaymentService {
    private static final Logger log = LoggerFactory.getLogger(PaymentServiceImpl.class);

    private final PaymentRepository paymentRepository;
    private final OwnerRepository ownerRepository;
    private final PaymentMapper paymentMapper;
    private final Sheets sheetsService;

    private static final Pattern SHEET_ID_PATTERN = Pattern.compile("/spreadsheets/d/([a-zA-Z0-9-_]+)");

    @Autowired
    public PaymentServiceImpl(PaymentRepository paymentRepository,
                          OwnerRepository ownerRepository,
                          PaymentMapper paymentMapper,
                          Sheets sheetsService) {
        this.paymentRepository = paymentRepository;
        this.ownerRepository = ownerRepository;
        this.paymentMapper = paymentMapper;
        this.sheetsService = sheetsService;
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

    if (paymentRequest.getOwnerId() != null) {
        int index = i;
        Owner owner = ownerRepository.findById(paymentRequest.getOwnerId())
                .orElseThrow(() -> {
                    log.error("Owner not found with id: {} for payment request at index {}", paymentRequest.getOwnerId(), index);
                    return new ResourceNotFoundException("Owner not found with id: " + paymentRequest.getOwnerId() + " for payment at index " + index + ".");
                });
        payment.setOwner(owner);
    } else {
        payment.setOwner(null);
    }
    paymentsToSave.add(payment);
}

        List<Payment> savedPayments = paymentRepository.saveAll(paymentsToSave);
        log.info("Successfully saved {} payments in a single transaction.", savedPayments.size());

        return new BulkAddPaymentsResponseDto(savedPayments.size(), new ArrayList<>());
    }

    @Override
    @Transactional(readOnly = true)
    public List<ParsedPaymentDto> parseSheet(String sheetUrl) {
        try {
            // 1. Extract Spreadsheet ID from URL
            String spreadsheetId = extractSheetId(sheetUrl);
            if (spreadsheetId == null) {
                throw new IllegalArgumentException("Invalid Google Sheet URL provided.");
            }

            // Define the range to read. Assumes data is on a sheet named 'Sheet1'.
            // Change 'Sheet1' if your sheet has a different name.
            // A:I covers all columns from Timestamp to Visits.
            final String range = "Form!A4000:I4020";

            // 2. Fetch data from Google Sheets API
            ValueRange response = sheetsService.spreadsheets().values()
                    .get(spreadsheetId, range)
                    .execute();

            List<List<Object>> values = response.getValues();
            if (values == null || values.isEmpty()) {
                return new ArrayList<>();
            }

            // 3. Fetch all owners from DB once for efficient matching
            List<Owner> allOwners = ownerRepository.findAll();

            // 4. Process each row from the sheet
            List<ParsedPaymentDto> parsedPayments = new ArrayList<>();
            // Skip header row (i = 0)
            for (int i = 1; i < values.size(); i++) {
                List<Object> row = values.get(i);
                ParsedPaymentDto dto = new ParsedPaymentDto();

                // Safely get values from row
                String timestamp = getCellStringValue(row, 0);
                String earningsStr = getCellStringValue(row, 5); // Column F
                String method = getCellStringValue(row, 6);      // Column G
                String clientName = getCellStringValue(row, 7);   // Column H
                String visitsStr = getCellStringValue(row, 8);    // Column I

                // Skip row if essential data like timestamp or earnings is missing
                if (!StringUtils.hasText(timestamp) || !StringUtils.hasText(earningsStr)) {
                    continue;
                }

                dto.setTimestamp(timestamp);
                dto.setMethod(method);
                dto.setClientName(clientName);

                try {
                    dto.setEarnings(new BigDecimal(earningsStr));
                } catch (NumberFormatException e) {
                    // Handle cases where earnings is not a valid number, maybe log it
                    // For now, we'll skip this payment or set it to zero
                    dto.setEarnings(BigDecimal.ZERO);
                }

                if (StringUtils.hasText(visitsStr)) {
                    try {
                        dto.setVisits(Integer.parseInt(visitsStr));
                    } catch (NumberFormatException e) {
                        dto.setVisits(null); // Or handle error
                    }
                }
                
                // 5. Match client from sheet with DB owners
                if (StringUtils.hasText(clientName)) {
                    Owner matchedOwner = findMatchingOwner(clientName, allOwners);
                    if (matchedOwner != null) {
                        dto.setMatchedClientId(matchedOwner.getId());
                    }
                }

                parsedPayments.add(dto);
            }

            return parsedPayments;

        } catch (IOException e) {
            // A more specific exception might be better for the controller to handle
            throw new RuntimeException("Failed to read from Google Sheet. Check permissions and URL.", e);
        }
    }

    /**
     * Extracts the Google Sheet ID from a given URL.
     */
    private String extractSheetId(String url) {
        Matcher matcher = SHEET_ID_PATTERN.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Safely retrieves a string value from a row list, returning null if the index is out of bounds.
     */
    private String getCellStringValue(List<Object> row, int index) {
        if (row != null && index < row.size()) {
            Object cell = row.get(index);
            return cell != null ? cell.toString() : null;
        }
        return null;
    }

    /**
     * Attempts to find a matching owner from a list of all owners based on the client name string.
     * The matching logic is case-insensitive and checks against first name, last name, full name, and pet names.
     */
    private Owner findMatchingOwner(String clientName, List<Owner> allOwners) {
        String normalizedClientName = clientName.trim().toLowerCase();

        for (Owner owner : allOwners) {
            String firstName = owner.getFirstName().toLowerCase();
            String lastName = owner.getLastName().toLowerCase();
            String fullName = (firstName + " " + lastName);

            // Match 1: Exact full name match
            if (fullName.equals(normalizedClientName)) {
                return owner;
            }
            
            // Match 2: Client name contains first or last name
            if (normalizedClientName.contains(firstName) || normalizedClientName.contains(lastName)) {
                return owner;
            }

            // Match 3: Check against pet names
            for (String petName : owner.getPets()) {
                if (normalizedClientName.contains(petName.toLowerCase())) {
                    return owner;
                }
            }
        }

        // No match found
        return null;
    }
}
