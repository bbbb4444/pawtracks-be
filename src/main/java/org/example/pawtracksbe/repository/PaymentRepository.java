package org.example.pawtracksbe.repository;

import org.example.pawtracksbe.entity.Payment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
    Optional<Payment> findById(long id);
}
