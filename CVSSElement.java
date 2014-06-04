/**
 * CVSS Element - Common Vulnerability Scoring System element class (CVSSElement.java)
 * Copyright (C) 2014  Carter Yagemann
 *
 *
 * This is a simple object for evaluating the CVSS score for vulnerabilities. The CVSS parameters
 * can be set and modified and then the score can be calculated.
 *
 * The parameters should be set using the public constants defined in the object. Refer to the
 * README for more information.
 *
 * This class is based on version 2 of the CVSS standard. More information can be found at:
 * http://www.first.org/cvss/cvss-guide .
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.yagemann.cvss;

public class CVSSElement {

    /* Begin CVSS parameters */

    // Base variables
    private double ACCESS_VECTOR;
    private double ACCESS_COMPLEXITY;
    private double AUTHENTICATION;
    private double CONFIDENTIALITY_IMPACT;
    private double INTEGRITY_IMPACT;
    private double AVAILABILITY_IMPACT;

    // Temporal variables
    private double EXPLOITABILITY;
    private double REMEDIATION_LEVEL;
    private double REPORT_CONFIDENCE;

    // Environmental variables
    private double COLLATERAL_DAMAGE;
    private double TARGET_DISTRIBUTION;
    private double CONFIDENTIALITY_REQUIREMENT;
    private double INTEGRITY_REQUIREMENT;
    private double AVAILABILITY_REQUIREMENT;

    /* End CVSS paramters */

    /* Begin Constants */

    // Access Vector
    final public double ACCESS_VECTOR_REQUIRES_LOCAL_ACCESS = 0.395;
    final public double ACCESS_VECTOR_ADJACENT_NETWORK_ACCESSIBLE = 0.646;
    final public double ACCESS_VECTOR_NETWORK_ACCESSIBLE = 1.0;

    // Access Complexity
    final public double ACCESS_COMPLEXITY_HIGH = 0.35;
    final public double ACCESS_COMPLEXITY_MEDIUM = 0.61;
    final public double ACCESS_COMPLEXITY_LOW = 0.71;

    // Authentication
    final public double AUTHENTICATION_REQUIRES_MULTIPLE_INSTANCES = 0.45;
    final public double AUTHENTICATION_REQUIRES_SINGLE_INSTANCE = 0.56;
    final public double AUTHENTICATION_REQUIRES_NO_AUTHENTICATION = 0.704;

    // Confidentiality Impact
    final public double CONFIDENTIALITY_IMPACT_NONE = 0.0;
    final public double CONFIDENTIALITY_IMPACT_PARTIAL = 0.275;
    final public double CONFIDENTIALITY_IMPACT_COMPLETE = 0.660;

    // Integrity Impact
    final public double INTEGRITY_IMPACT_NONE = 0.0;
    final public double INTEGRITY_IMPACT_PARTIAL = 0.275;
    final public double INTEGRITY_IMPACT_COMPLETE = 0.660;

    // Availability Impact
    final public double AVAILABILITY_IMPACT_NONE = 0.0;
    final public double AVAILABILITY_IMPACT_PARTIAL = 0.275;
    final public double AVAILABILITY_IMPACT_COMPLETE = 0.660;

    // Exploitability
    final public double EXPLOITABILITY_UNPROVEN = 0.85;
    final public double EXPLOITABILITY_PROOF_OF_CONCEPT = 0.9;
    final public double EXPLOITABILITY_FUNCTIONAL = 0.95;
    final public double EXPLOITABILITY_HIGH = 1.0;
    final public double EXPLOITABILITY_NOT_DEFINED = 1.0;

    // Remediation Level
    final public double REMEDIATION_LEVEL_OFFICIAL_FIX = 0.87;
    final public double REMEDIATION_LEVEL_TEMPORARY_FIX = 0.9;
    final public double REMEDIATION_LEVEL_WORKAROUND = 0.95;
    final public double REMEDIATION_LEVEL_UNAVAILABLE = 1.0;
    final public double REMEDIATION_LEVEL_NOT_DEFINED = 1.0;

    // Report Confidence
    final public double REPORT_CONFIDENCE_UNCONFIRMED = 0.9;
    final public double REPORT_CONFIDENCE_UNCORROBORATED = 0.95;
    final public double REPORT_CONFIDENCE_CONFIRMED = 1.0;
    final public double REPORT_CONFIDENCE_NOT_DEFINED = 1.0;

    // Collateral Damage
    final public double COLLATERAL_DAMAGE_NONE = 0.0;
    final public double COLLATERAL_DAMAGE_LOW = 0.1;
    final public double COLLATERAL_DAMAGE_LOW_MEDIUM = 0.3;
    final public double COLLATERAL_DAMAGE_MEDIUM_HIGH = 0.4;
    final public double COLLATERAL_DAMAGE_HIGH = 0.5;
    final public double COLLATERAL_DAMAGE_NOT_DEFINED = 0.0;

    // Target Distribution
    final public double TARGET_DISTRIBUTION_NONE = 0.0;
    final public double TARGET_DISTRIBUTION_LOW = 0.25;
    final public double TARGET_DISTRIBUTION_MEDIUM = 0.75;
    final public double TARGET_DISTRIBUTION_HIGH = 1.0;
    final public double TARGET_DISTRIBUTION_NOT_DEFINED = 1.0;

    // Confidentiality Requirement
    final public double CONFIDENTIALITY_REQUIREMENT_LOW = 0.5;
    final public double CONFIDENTIALITY_REQUIREMENT_MEDIUM = 1.0;
    final public double CONFIDENTIALITY_REQUIREMENT_HIGH = 1.51;
    final public double CONFIDENTIALITY_REQUIREMENT_NOT_DEFINED = 1.0;

    // Integrity Requirement
    final public double INTEGRITY_REQUIREMENT_LOW = 0.5;
    final public double INTEGRITY_REQUIREMENT_MEDIUM = 1.0;
    final public double INTEGRITY_REQUIREMENT_HIGH = 1.51;
    final public double INTEGRITY_REQUIREMENT_NOT_DEFINED = 1.0;

    // Availability Requirement
    final public double AVAILABILITY_REQUIREMENT_LOW = 0.5;
    final public double AVAILABILITY_REQUIREMENT_MEDIUM = 1.0;
    final public double AVAILABILITY_REQUIREMENT_HIGH = 1.51;
    final public double AVAILABILITY_REQUIREMENT_NOT_DEFINED = 1.0;

    /* End Constants */

    /**
     * Basic constructor
     * Takes no parameters and initializes everything to NaN
     */
    public void CVSSElement() {
        ACCESS_VECTOR = Double.NaN;
        ACCESS_COMPLEXITY = Double.NaN;
        AUTHENTICATION = Double.NaN;
        CONFIDENTIALITY_IMPACT = Double.NaN;
        INTEGRITY_IMPACT = Double.NaN;
        AVAILABILITY_IMPACT = Double.NaN;

        EXPLOITABILITY = Double.NaN;
        REMEDIATION_LEVEL = Double.NaN;
        REPORT_CONFIDENCE = Double.NaN;

        COLLATERAL_DAMAGE = Double.NaN;
        TARGET_DISTRIBUTION = Double.NaN;
        CONFIDENTIALITY_REQUIREMENT = Double.NaN;
        INTEGRITY_REQUIREMENT = Double.NaN;
        AVAILABILITY_REQUIREMENT = Double.NaN;
    }

    /**
     * Constructor for only setting base variables
     */
    public void CVSSElement(double accessVector, double accessComplexity, double authentication,
                            double confidentialityImpact, double integrityImpact,
                            double availabilityImpact) {
        ACCESS_VECTOR = accessVector;
        ACCESS_COMPLEXITY = accessComplexity;
        AUTHENTICATION = authentication;
        CONFIDENTIALITY_IMPACT = confidentialityImpact;
        INTEGRITY_IMPACT = integrityImpact;
        AVAILABILITY_IMPACT = availabilityImpact;

        EXPLOITABILITY = Double.NaN;
        REMEDIATION_LEVEL = Double.NaN;
        REPORT_CONFIDENCE = Double.NaN;

        COLLATERAL_DAMAGE = Double.NaN;
        TARGET_DISTRIBUTION = Double.NaN;
        CONFIDENTIALITY_REQUIREMENT = Double.NaN;
        INTEGRITY_REQUIREMENT = Double.NaN;
        AVAILABILITY_REQUIREMENT = Double.NaN;
    }

    /**
     * Constructor for setting all variables
     */
    public void CVSSElement(double accessVector, double accessComplexity, double authentication,
                            double confidentialityImpact, double integrityImpact,
                            double availabilityImpact, double exploitability,
                            double remediationLevel, double reportConfidence,
                            double collateralDamage, double targetDistribution,
                            double confidentialityRequirement, double integrityRequirement,
                            double availabilityRequirement) {
        ACCESS_VECTOR = accessVector;
        ACCESS_COMPLEXITY = accessComplexity;
        AUTHENTICATION = authentication;
        CONFIDENTIALITY_IMPACT = confidentialityImpact;
        INTEGRITY_IMPACT = integrityImpact;
        AVAILABILITY_IMPACT = availabilityImpact;

        EXPLOITABILITY = exploitability;
        REMEDIATION_LEVEL = remediationLevel;
        REPORT_CONFIDENCE = reportConfidence;

        COLLATERAL_DAMAGE = collateralDamage;
        TARGET_DISTRIBUTION = targetDistribution;
        CONFIDENTIALITY_REQUIREMENT = confidentialityRequirement;
        INTEGRITY_REQUIREMENT = integrityRequirement;
        AVAILABILITY_REQUIREMENT = availabilityRequirement;
    }

    /* Begin Getters */

    public double getAccessVector() {return ACCESS_VECTOR;}
    public double getAccessComplexity() {return ACCESS_COMPLEXITY;}
    public double getAuthentication() {return AUTHENTICATION;}
    public double getConfidentialityImpact() {return CONFIDENTIALITY_IMPACT;}
    public double getIntegrityImpact() {return INTEGRITY_IMPACT;}
    public double getAvailabilityImpact() {return AVAILABILITY_IMPACT;}

    public double getExploitability() {return EXPLOITABILITY;}
    public double getRemediationLevel() {return REMEDIATION_LEVEL;}
    public double getReportConfidence() {return REPORT_CONFIDENCE;}

    public double getCollateralDamage() {return COLLATERAL_DAMAGE;}
    public double getTargetDistribution() {return TARGET_DISTRIBUTION;}
    public double getConfidentialityRequirement() {return CONFIDENTIALITY_REQUIREMENT;}
    public double getIntegrityRequirement() {return INTEGRITY_REQUIREMENT;}
    public double getAvailabilityRequirement() {return AVAILABILITY_REQUIREMENT;}

    /* End Getters */

    /* Begin Setters */

    public void setAccessVector(double accessVector) {
        ACCESS_VECTOR= accessVector;
    }
    public void setAccessComplexity(double accessComplexity) {
        ACCESS_COMPLEXITY = accessComplexity;
    }
    public void setAuthentication(double authentication) {
        AUTHENTICATION = authentication;
    }
    public void setConfidentialityImpact(double confidentialityImpact) {
        CONFIDENTIALITY_IMPACT = confidentialityImpact;
    }
    public void setIntegrityImpact(double integrityImpact) {
        INTEGRITY_IMPACT = integrityImpact;
    }
    public void setAvailabilityImpact(double availabilityImpact) {
        AVAILABILITY_IMPACT = availabilityImpact;
    }

    public void setExploitability(double exploitability) {
        EXPLOITABILITY = exploitability;
    }
    public void setRemediationLevel(double remediationLevel) {
        REMEDIATION_LEVEL = remediationLevel;
    }
    public void setReportConfidence(double reportConfidence) {
        REPORT_CONFIDENCE = reportConfidence;
    }

    public void setCollateralDamage(double collateralDamage) {
        COLLATERAL_DAMAGE = collateralDamage;
    }
    public void setTargetDistribution(double targetDistribution) {
        TARGET_DISTRIBUTION = targetDistribution;
    }
    public void setConfidentialityRequirement(double confidentialityRequirement) {
        CONFIDENTIALITY_REQUIREMENT = confidentialityRequirement;
    }
    public void setIntegrityRequirement(double integrityRequirement) {
        INTEGRITY_REQUIREMENT = integrityRequirement;
    }
    public void setAvailabilityRequirement(double availabilityRequirement) {
        AVAILABILITY_REQUIREMENT = availabilityRequirement;
    }

    /* End Setters */

    /* Other methods */

    /**
     * Verifies all the parameters needed to calculate the base score have been set to some values
     * @return True if base parameters have been set, otherwise throws IllegalArgumentException
     */
    private boolean verifyBaseParameters() {
        if (ACCESS_VECTOR == Double.NaN)
            throw new IllegalArgumentException("Access Vector has not been set");

        if (ACCESS_COMPLEXITY == Double.NaN)
            throw new IllegalArgumentException("Access Complexity has not been set");

        if (AUTHENTICATION == Double.NaN)
            throw new IllegalArgumentException("Authentication has not been set");

        if (CONFIDENTIALITY_IMPACT == Double.NaN)
            throw new IllegalArgumentException("Confidentiality Impact has not been set");

        if (INTEGRITY_IMPACT == Double.NaN)
            throw new IllegalArgumentException("Integrity Impact has not been set");

        if (AVAILABILITY_IMPACT == Double.NaN)
            throw new IllegalArgumentException("Availability Impact has not been set");

        return true;
    }

    /**
     * Verifies all the parameters needed to calculate the full score have been set to some values
     * @return True if all parameters have been set, otherwise throws IllegalArgumentException
     */
    private boolean verifyAllParameters() {
        // Verify base parameters have been set
        try {
            verifyBaseParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        // Verify optional parameters have been set
        if (EXPLOITABILITY == Double.NaN)
            throw new IllegalArgumentException("Exploitability has not been set");

        if (REMEDIATION_LEVEL == Double.NaN)
            throw new IllegalArgumentException("Remediation Level has not been set");

        if (REPORT_CONFIDENCE == Double.NaN)
            throw new IllegalArgumentException("Report Confidence has not been set");

        if (COLLATERAL_DAMAGE == Double.NaN)
            throw new IllegalArgumentException("Collateral Damage has not been set");

        if (TARGET_DISTRIBUTION == Double.NaN)
            throw new IllegalArgumentException("Target Distribution has not been set");

        if (CONFIDENTIALITY_REQUIREMENT == Double.NaN)
            throw new IllegalArgumentException("Confidentiality Requirement has not been set");

        if (INTEGRITY_REQUIREMENT == Double.NaN)
            throw new IllegalArgumentException("Integrity Requirement has not been set");

        if (AVAILABILITY_REQUIREMENT == Double.NaN)
            throw new IllegalArgumentException("Availability Requirement has not been set");

        return true;
    }

    /**
     * Verifies base parameters have been set and then calculates base score
     * @return Double representing base score
     */
    public double calculateBaseScore() {
        // Verify parameters have been set
        try {
            verifyBaseParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        double score, f;

        // Calculate base score
        double impact = 10.41*(1-(1-CONFIDENTIALITY_IMPACT)*(1-INTEGRITY_IMPACT)*(1-AVAILABILITY_IMPACT));
        if (impact == 0) f = 0; else f = 1.176;
        double exploitability = 20*ACCESS_VECTOR*ACCESS_COMPLEXITY*AUTHENTICATION;
        score = ((0.6*impact)+(0.4*exploitability)-1.5)*f;

        return score;
    }

    /**
     * Verifies all parameters have been set and calculates temporal score
     * @return Double representing temporal score
     */
    private double calculateTemporalScore(double baseScore) {
        try {
            verifyAllParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        double score = baseScore* EXPLOITABILITY *REMEDIATION_LEVEL*REPORT_CONFIDENCE;

        return score;
    }

    /**
     * Verifies all parameters have been set and calculates environmental score
     * @return Double representing environmental score
     */
    private double calculateEnvironmentalScore() {
        try {
            verifyAllParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        double adjustedImpact = Math.min(10, 10.41*(1-(1-CONFIDENTIALITY_IMPACT*CONFIDENTIALITY_REQUIREMENT)*
                                                      (1-INTEGRITY_IMPACT*INTEGRITY_REQUIREMENT)*
                                                      (1-AVAILABILITY_IMPACT*AVAILABILITY_REQUIREMENT)));
        double f;
        if (adjustedImpact == 0) f = 0; else f = 1.176;
        double exploitability = 20*ACCESS_VECTOR*ACCESS_COMPLEXITY*AUTHENTICATION;

        double adjustedBase = ((0.6*adjustedImpact)+(0.4*exploitability)-1.5)*f;

        double adjustedTemporal = adjustedBase* EXPLOITABILITY *REMEDIATION_LEVEL*REPORT_CONFIDENCE;

        double score = (adjustedTemporal+(10-adjustedTemporal)*COLLATERAL_DAMAGE)*TARGET_DISTRIBUTION;

        return score;
    }

    /**
     * Verifies all parameters have been set and then calculates full score
     * @return Double array containing the base, temporal and environmental scores in that order
     */
    public double[] calculateScores() {
        // Verify parameters have been set
        try {
            verifyAllParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        // Calculate base score
        double baseScore = calculateBaseScore();

        // Calculate temporal score
        double temporalScore = calculateTemporalScore(baseScore);

        // Calculate environmental score
        double environmentalScore = calculateEnvironmentalScore();

        double scores[] = {baseScore, temporalScore, environmentalScore};

        return scores;
    }
}
