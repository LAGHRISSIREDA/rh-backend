package com.veinsmoke.myrhbackend.repository;

import com.veinsmoke.myrhbackend.entity.JobOffer;
import com.veinsmoke.myrhbackend.entity.projections.JobOfferDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

@RepositoryRestResource(excerptProjection = JobOfferDetail.class)
public interface JobOfferRepository extends JpaRepository<JobOffer, Long> {
}

