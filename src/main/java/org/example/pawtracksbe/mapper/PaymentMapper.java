
package org.example.pawtracksbe.mapper;

import org.example.pawtracksbe.dto.CreatePaymentRequestDto;
import org.example.pawtracksbe.dto.OwnerSummaryDto;
import org.example.pawtracksbe.dto.PaymentResponseDto;
import org.example.pawtracksbe.dto.UpdatePaymentRequestDto;
import org.example.pawtracksbe.entity.Owner;
import org.example.pawtracksbe.entity.Payment;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValuePropertyMappingStrategy;

import java.util.List;

@Mapper(componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface PaymentMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "owner", ignore = true)
    Payment createPaymentRequestDtoToPayment(CreatePaymentRequestDto dto);

    @Mapping(source = "owner", target = "owner")
    PaymentResponseDto paymentToPaymentResponseDto(Payment payment);

    List<PaymentResponseDto> paymentsToPaymentResponseDtos(List<Payment> payments);

    @Mapping(target = "id", ignore = true)
    void updatePaymentFromDto(UpdatePaymentRequestDto dto, @MappingTarget Payment payment);

    OwnerSummaryDto ownerToOwnerSummaryDto(Owner owner);
}