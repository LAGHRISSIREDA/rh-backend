package com.veinsmoke.myrhbackend.controller;


import com.veinsmoke.myrhbackend.entity.Company;
import com.veinsmoke.myrhbackend.entity.JobOffer;
import com.veinsmoke.myrhbackend.mapstruct.dtos.JobOfferDto;
import com.veinsmoke.myrhbackend.mapstruct.mappers.JobOfferMapper;
import com.veinsmoke.myrhbackend.service.company.CompanyService;
import com.veinsmoke.myrhbackend.service.joboffer.JobOfferService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequiredArgsConstructor
@RequestMapping("/jobOffer")
@Slf4j
public class JobOfferController {

    private final JobOfferService jobOfferService;
    private final JobOfferMapper jobOfferMapper;
    private final CompanyService companyService;

    @PostMapping("/add")
    public ResponseEntity<HashMap<String, String>> createJobOffer(@Valid @RequestBody JobOfferDto jobOfferDto) {
        // throw exception if company not found
        Company company = companyService.getCompanyByEmail(jobOfferDto.getEmail()).orElseThrow(() -> new RuntimeException("Company not found"));

        // map dto to entity
        JobOffer jobOffer = jobOfferMapper.jobOfferDtoToJobOffer(jobOfferDto);
        jobOffer.setCompany(company);

        // save job offer
        jobOfferService.create(jobOffer);

        // return response
        HashMap<String, String> response = new HashMap<>();
        response.put("message", "Job offer created");
        return ResponseEntity.ok(response);
    }
}
