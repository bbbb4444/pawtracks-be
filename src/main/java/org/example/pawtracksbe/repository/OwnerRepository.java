package org.example.pawtracksbe.repository;

import org.example.pawtracksbe.entity.Owner;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OwnerRepository extends JpaRepository<Owner, Long> {
    Optional<Owner> findById(long id);
}
