package com.veinsmoke.myrhbackend.entity.projections;

import com.veinsmoke.myrhbackend.entity.Company;
import com.veinsmoke.myrhbackend.entity.JobOffer;
import com.veinsmoke.myrhbackend.enums.JobState;
import com.veinsmoke.myrhbackend.enums.JobType;
import com.veinsmoke.myrhbackend.enums.SalaryType;
import org.springframework.data.rest.core.config.Projection;

@Projection(name = "offerDetail", types = { JobOffer.class })
public interface JobOfferDetail {
    String getProfile();
    String getDescription();
    String getCountry();
    JobType getJobType();
    Double getSalary();
    SalaryType getSalaryType();
    JobState getState();
    Company getCompany();
}
