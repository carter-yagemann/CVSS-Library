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

    /**
     * Class for representing the variables. Simply contains an id and value pair
     */
    private class CVSSVariable {
        public int ID;
        public double VALUE;

        CVSSVariable(int id, double value) {
            ID = id;
            VALUE = value;
        }
    }

    /* Begin CVSS parameters */

    // Base variables
    private CVSSVariable ACCESS_VECTOR;
    private CVSSVariable ACCESS_COMPLEXITY;
    private CVSSVariable AUTHENTICATION;
    private CVSSVariable CONFIDENTIALITY_IMPACT;
    private CVSSVariable INTEGRITY_IMPACT;
    private CVSSVariable AVAILABILITY_IMPACT;

    // Temporal variables
    private CVSSVariable EXPLOITABILITY;
    private CVSSVariable REMEDIATION_LEVEL;
    private CVSSVariable REPORT_CONFIDENCE;

    // Environmental variables
    private CVSSVariable COLLATERAL_DAMAGE;
    private CVSSVariable TARGET_DISTRIBUTION;
    private CVSSVariable CONFIDENTIALITY_REQUIREMENT;
    private CVSSVariable INTEGRITY_REQUIREMENT;
    private CVSSVariable AVAILABILITY_REQUIREMENT;

    /* End CVSS paramters */

    /* Begin Constants */

    // Access Vector
    final public CVSSVariable ACCESS_VECTOR_REQUIRES_LOCAL_ACCESS = new CVSSVariable(0, 0.395);
    final public CVSSVariable ACCESS_VECTOR_ADJACENT_NETWORK_ACCESSIBLE = new CVSSVariable(1, 0.646);
    final public CVSSVariable ACCESS_VECTOR_NETWORK_ACCESSIBLE = new CVSSVariable(2, 1.0);

    // Access Complexity
    final public CVSSVariable ACCESS_COMPLEXITY_HIGH = new CVSSVariable(0, 0.35);
    final public CVSSVariable ACCESS_COMPLEXITY_MEDIUM = new CVSSVariable(1, 0.61);
    final public CVSSVariable ACCESS_COMPLEXITY_LOW = new CVSSVariable(2, 0.71);

    // Authentication
    final public CVSSVariable AUTHENTICATION_REQUIRES_MULTIPLE_INSTANCES = new CVSSVariable(0, 0.45);
    final public CVSSVariable AUTHENTICATION_REQUIRES_SINGLE_INSTANCE = new CVSSVariable (1, 0.56);
    final public CVSSVariable AUTHENTICATION_REQUIRES_NO_AUTHENTICATION = new CVSSVariable(2, 0.704);

    // Confidentiality Impact
    final public CVSSVariable CONFIDENTIALITY_IMPACT_NONE = new CVSSVariable(0, 0.0);
    final public CVSSVariable CONFIDENTIALITY_IMPACT_PARTIAL = new CVSSVariable(1, 0.275);
    final public CVSSVariable CONFIDENTIALITY_IMPACT_COMPLETE = new CVSSVariable(2, 0.660);

    // Integrity Impact
    final public CVSSVariable INTEGRITY_IMPACT_NONE = new CVSSVariable(0, 0.0);
    final public CVSSVariable INTEGRITY_IMPACT_PARTIAL = new CVSSVariable(1, 0.275);
    final public CVSSVariable INTEGRITY_IMPACT_COMPLETE = new CVSSVariable(2, 0.660);

    // Availability Impact
    final public CVSSVariable AVAILABILITY_IMPACT_NONE = new CVSSVariable(0, 0.0);
    final public CVSSVariable AVAILABILITY_IMPACT_PARTIAL = new CVSSVariable(1, 0.275);
    final public CVSSVariable AVAILABILITY_IMPACT_COMPLETE = new CVSSVariable(2, 0.660);

    // Exploitability
    final public CVSSVariable EXPLOITABILITY_UNPROVEN = new CVSSVariable(0, 0.85);
    final public CVSSVariable EXPLOITABILITY_PROOF_OF_CONCEPT = new CVSSVariable(1, 0.9);
    final public CVSSVariable EXPLOITABILITY_FUNCTIONAL = new CVSSVariable(2, 0.95);
    final public CVSSVariable EXPLOITABILITY_HIGH = new CVSSVariable(3, 1.0);
    final public CVSSVariable EXPLOITABILITY_NOT_DEFINED = new CVSSVariable(4, 1.0);

    // Remediation Level
    final public CVSSVariable REMEDIATION_LEVEL_OFFICIAL_FIX = new CVSSVariable(0, 0.87);
    final public CVSSVariable REMEDIATION_LEVEL_TEMPORARY_FIX = new CVSSVariable(1, 0.9);
    final public CVSSVariable REMEDIATION_LEVEL_WORKAROUND = new CVSSVariable(2, 0.95);
    final public CVSSVariable REMEDIATION_LEVEL_UNAVAILABLE = new CVSSVariable(3, 1.0);
    final public CVSSVariable REMEDIATION_LEVEL_NOT_DEFINED = new CVSSVariable(4, 1.0);

    // Report Confidence
    final public CVSSVariable REPORT_CONFIDENCE_UNCONFIRMED = new CVSSVariable(0, 0.9);
    final public CVSSVariable REPORT_CONFIDENCE_UNCORROBORATED = new CVSSVariable(1, 0.95);
    final public CVSSVariable REPORT_CONFIDENCE_CONFIRMED = new CVSSVariable(2, 1.0);
    final public CVSSVariable REPORT_CONFIDENCE_NOT_DEFINED = new CVSSVariable(3, 1.0);

    // Collateral Damage
    final public CVSSVariable COLLATERAL_DAMAGE_NONE = new CVSSVariable(0, 0.0);
    final public CVSSVariable COLLATERAL_DAMAGE_LOW = new CVSSVariable(1, 0.1);
    final public CVSSVariable COLLATERAL_DAMAGE_LOW_MEDIUM = new CVSSVariable(2, 0.3);
    final public CVSSVariable COLLATERAL_DAMAGE_MEDIUM_HIGH = new CVSSVariable(3, 0.4);
    final public CVSSVariable COLLATERAL_DAMAGE_HIGH = new CVSSVariable(4, 0.5);
    final public CVSSVariable COLLATERAL_DAMAGE_NOT_DEFINED = new CVSSVariable(5, 0.0);

    // Target Distribution
    final public CVSSVariable TARGET_DISTRIBUTION_NONE = new CVSSVariable(0, 0.0);
    final public CVSSVariable TARGET_DISTRIBUTION_LOW = new CVSSVariable(1, 0.25);
    final public CVSSVariable TARGET_DISTRIBUTION_MEDIUM = new CVSSVariable(2, 0.75);
    final public CVSSVariable TARGET_DISTRIBUTION_HIGH = new CVSSVariable(3, 1.0);
    final public CVSSVariable TARGET_DISTRIBUTION_NOT_DEFINED = new CVSSVariable(4, 1.0);

    // Confidentiality Requirement
    final public CVSSVariable CONFIDENTIALITY_REQUIREMENT_LOW = new CVSSVariable(0, 0.5);
    final public CVSSVariable CONFIDENTIALITY_REQUIREMENT_MEDIUM = new CVSSVariable(1, 1.0);
    final public CVSSVariable CONFIDENTIALITY_REQUIREMENT_HIGH = new CVSSVariable(2, 1.51);
    final public CVSSVariable CONFIDENTIALITY_REQUIREMENT_NOT_DEFINED = new CVSSVariable(3, 1.0);

    // Integrity Requirement
    final public CVSSVariable INTEGRITY_REQUIREMENT_LOW = new CVSSVariable(0, 0.5);
    final public CVSSVariable INTEGRITY_REQUIREMENT_MEDIUM = new CVSSVariable(1, 1.0);
    final public CVSSVariable INTEGRITY_REQUIREMENT_HIGH = new CVSSVariable(2, 1.51);
    final public CVSSVariable INTEGRITY_REQUIREMENT_NOT_DEFINED = new CVSSVariable(3, 1.0);

    // Availability Requirement
    final public CVSSVariable AVAILABILITY_REQUIREMENT_LOW = new CVSSVariable(0, 0.5);
    final public CVSSVariable AVAILABILITY_REQUIREMENT_MEDIUM = new CVSSVariable(1, 1.0);
    final public CVSSVariable AVAILABILITY_REQUIREMENT_HIGH = new CVSSVariable(2, 1.51);
    final public CVSSVariable AVAILABILITY_REQUIREMENT_NOT_DEFINED = new CVSSVariable(3, 1.0);

    /* End Constants */

    /**
     * Basic constructor
     * Takes no parameters and initializes everything to NaN
     */
    public void CVSSElement() {
        ACCESS_VECTOR = null;
        ACCESS_COMPLEXITY = null;
        AUTHENTICATION = null;
        CONFIDENTIALITY_IMPACT = null;
        INTEGRITY_IMPACT = null;
        AVAILABILITY_IMPACT = null;

        EXPLOITABILITY = null;
        REMEDIATION_LEVEL = null;
        REPORT_CONFIDENCE = null;

        COLLATERAL_DAMAGE = null;
        TARGET_DISTRIBUTION = null;
        CONFIDENTIALITY_REQUIREMENT = null;
        INTEGRITY_REQUIREMENT = null;
        AVAILABILITY_REQUIREMENT = null;
    }

    /**
     * Constructor for only setting base variables
     */
    public void CVSSElement(CVSSVariable accessVector, CVSSVariable accessComplexity, CVSSVariable authentication,
                            CVSSVariable confidentialityImpact, CVSSVariable integrityImpact,
                            CVSSVariable availabilityImpact) {
        ACCESS_VECTOR = accessVector;
        ACCESS_COMPLEXITY = accessComplexity;
        AUTHENTICATION = authentication;
        CONFIDENTIALITY_IMPACT = confidentialityImpact;
        INTEGRITY_IMPACT = integrityImpact;
        AVAILABILITY_IMPACT = availabilityImpact;

        EXPLOITABILITY = null;
        REMEDIATION_LEVEL = null;
        REPORT_CONFIDENCE = null;

        COLLATERAL_DAMAGE = null;
        TARGET_DISTRIBUTION = null;
        CONFIDENTIALITY_REQUIREMENT = null;
        INTEGRITY_REQUIREMENT = null;
        AVAILABILITY_REQUIREMENT = null;
    }

    /**
     * Constructor for setting all variables
     */
    public void CVSSElement(CVSSVariable accessVector, CVSSVariable accessComplexity, CVSSVariable authentication,
                            CVSSVariable confidentialityImpact, CVSSVariable integrityImpact,
                            CVSSVariable availabilityImpact, CVSSVariable exploitability,
                            CVSSVariable remediationLevel, CVSSVariable reportConfidence,
                            CVSSVariable collateralDamage, CVSSVariable targetDistribution,
                            CVSSVariable confidentialityRequirement, CVSSVariable integrityRequirement,
                            CVSSVariable availabilityRequirement) {
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

    public int getAccessVectorId() {return ACCESS_VECTOR.ID;}
    public int getAccessComplexityId() {return ACCESS_COMPLEXITY.ID;}
    public int getAuthenticationId() {return AUTHENTICATION.ID;}
    public int getConfidentialityImpactId() {return CONFIDENTIALITY_IMPACT.ID;}
    public int getIntegrityImpactId() {return INTEGRITY_IMPACT.ID;}
    public int getAvailabilityImpactId() {return AVAILABILITY_IMPACT.ID;}

    public double getAccessVectorValue() {return ACCESS_VECTOR.VALUE;}
    public double getAccessComplexityValue() {return ACCESS_COMPLEXITY.VALUE;}
    public double getAuthenticationValue() {return AUTHENTICATION.VALUE;}
    public double getConfidentialityImpactValue() {return CONFIDENTIALITY_IMPACT.VALUE;}
    public double getIntegrityImpactValue() {return INTEGRITY_IMPACT.VALUE;}
    public double getAvailabilityImpactValue() {return AVAILABILITY_IMPACT.VALUE;}

    public int getExploitabilityId() {return EXPLOITABILITY.ID;}
    public int getRemediationLevelId() {return REMEDIATION_LEVEL.ID;}
    public int getReportConfidenceId() {return REPORT_CONFIDENCE.ID;}

    public double getExploitabilityValue() {return EXPLOITABILITY.VALUE;}
    public double getRemediationLevelValue() {return REMEDIATION_LEVEL.VALUE;}
    public double getReportConfidenceValue() {return REPORT_CONFIDENCE.VALUE;}

    public int getCollateralDamageId() {return COLLATERAL_DAMAGE.ID;}
    public int getTargetDistributionId() {return TARGET_DISTRIBUTION.ID;}
    public int getConfidentialityRequirementId() {return CONFIDENTIALITY_REQUIREMENT.ID;}
    public int getIntegrityRequirementId() {return INTEGRITY_REQUIREMENT.ID;}
    public int getAvailabilityRequirementId() {return AVAILABILITY_REQUIREMENT.ID;}

    public double getCollateralDamageValue() {return COLLATERAL_DAMAGE.VALUE;}
    public double getTargetDistributionValue() {return TARGET_DISTRIBUTION.VALUE;}
    public double getConfidentialityRequirementValue() {return CONFIDENTIALITY_REQUIREMENT.VALUE;}
    public double getIntegrityRequirementValue() {return INTEGRITY_REQUIREMENT.VALUE;}
    public double getAvailabilityRequirementValue() {return AVAILABILITY_REQUIREMENT.VALUE;}

    /* End Getters */

    /* Begin Setters */

    public void setAccessVector(CVSSVariable accessVector) {
        ACCESS_VECTOR = accessVector;
    }
    public void setAccessComplexity(CVSSVariable accessComplexity) {
        ACCESS_COMPLEXITY = accessComplexity;
    }
    public void setAuthentication(CVSSVariable authentication) {
        AUTHENTICATION = authentication;
    }
    public void setConfidentialityImpact(CVSSVariable confidentialityImpact) {
        CONFIDENTIALITY_IMPACT = confidentialityImpact;
    }
    public void setIntegrityImpact(CVSSVariable integrityImpact) {
        INTEGRITY_IMPACT = integrityImpact;
    }
    public void setAvailabilityImpact(CVSSVariable availabilityImpact) {
        AVAILABILITY_IMPACT = availabilityImpact;
    }

    public void setExploitability(CVSSVariable exploitability) {
        EXPLOITABILITY = exploitability;
    }
    public void setRemediationLevel(CVSSVariable remediationLevel) {
        REMEDIATION_LEVEL = remediationLevel;
    }
    public void setReportConfidence(CVSSVariable reportConfidence) {
        REPORT_CONFIDENCE = reportConfidence;
    }

    public void setCollateralDamage(CVSSVariable collateralDamage) {
        COLLATERAL_DAMAGE = collateralDamage;
    }
    public void setTargetDistribution(CVSSVariable targetDistribution) {
        TARGET_DISTRIBUTION = targetDistribution;
    }
    public void setConfidentialityRequirement(CVSSVariable confidentialityRequirement) {
        CONFIDENTIALITY_REQUIREMENT = confidentialityRequirement;
    }
    public void setIntegrityRequirement(CVSSVariable integrityRequirement) {
        INTEGRITY_REQUIREMENT = integrityRequirement;
    }
    public void setAvailabilityRequirement(CVSSVariable availabilityRequirement) {
        AVAILABILITY_REQUIREMENT = availabilityRequirement;
    }

    /* End Setters */

    /* Other methods */

    /**
     * Verifies all the parameters needed to calculate the base score have been set to some values
     * @return True if base parameters have been set, otherwise throws IllegalArgumentException
     */
    private boolean verifyBaseParameters() {
        if (ACCESS_VECTOR == null)
            throw new IllegalArgumentException("Access Vector has not been set");

        if (ACCESS_COMPLEXITY == null)
            throw new IllegalArgumentException("Access Complexity has not been set");

        if (AUTHENTICATION == null)
            throw new IllegalArgumentException("Authentication has not been set");

        if (CONFIDENTIALITY_IMPACT == null)
            throw new IllegalArgumentException("Confidentiality Impact has not been set");

        if (INTEGRITY_IMPACT == null)
            throw new IllegalArgumentException("Integrity Impact has not been set");

        if (AVAILABILITY_IMPACT == null)
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
        if (EXPLOITABILITY == null)
            throw new IllegalArgumentException("Exploitability has not been set");

        if (REMEDIATION_LEVEL == null)
            throw new IllegalArgumentException("Remediation Level has not been set");

        if (REPORT_CONFIDENCE == null)
            throw new IllegalArgumentException("Report Confidence has not been set");

        if (COLLATERAL_DAMAGE == null)
            throw new IllegalArgumentException("Collateral Damage has not been set");

        if (TARGET_DISTRIBUTION == null)
            throw new IllegalArgumentException("Target Distribution has not been set");

        if (CONFIDENTIALITY_REQUIREMENT == null)
            throw new IllegalArgumentException("Confidentiality Requirement has not been set");

        if (INTEGRITY_REQUIREMENT == null)
            throw new IllegalArgumentException("Integrity Requirement has not been set");

        if (AVAILABILITY_REQUIREMENT == null)
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
        double impact = 10.41*(1-(1-CONFIDENTIALITY_IMPACT.VALUE)*(1-INTEGRITY_IMPACT.VALUE)*(1-AVAILABILITY_IMPACT.VALUE));
        if (impact == 0) f = 0; else f = 1.176;
        double exploitability = 20 * ACCESS_VECTOR.VALUE * ACCESS_COMPLEXITY.VALUE * AUTHENTICATION.VALUE;
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

        double score = baseScore * EXPLOITABILITY.VALUE * REMEDIATION_LEVEL.VALUE * REPORT_CONFIDENCE.VALUE;

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

        double adjustedImpact = Math.min(10, 10.41*(1-(1-CONFIDENTIALITY_IMPACT.VALUE * CONFIDENTIALITY_REQUIREMENT.VALUE)*
                                                      (1-INTEGRITY_IMPACT.VALUE * INTEGRITY_REQUIREMENT.VALUE)*
                                                      (1-AVAILABILITY_IMPACT.VALUE * AVAILABILITY_REQUIREMENT.VALUE)));
        double f;
        if (adjustedImpact == 0) f = 0; else f = 1.176;
        double exploitability = 20 * ACCESS_VECTOR.VALUE * ACCESS_COMPLEXITY.VALUE * AUTHENTICATION.VALUE;

        double adjustedBase = ((0.6*adjustedImpact)+(0.4*exploitability)-1.5)*f;

        double adjustedTemporal = adjustedBase * EXPLOITABILITY.VALUE * REMEDIATION_LEVEL.VALUE * REPORT_CONFIDENCE.VALUE;

        double score = (adjustedTemporal+(10-adjustedTemporal)*COLLATERAL_DAMAGE.VALUE)*TARGET_DISTRIBUTION.VALUE;

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

    /**
     * Returns a string representation of the base vector
     * @return A string representation of the base vector
     */
    public String getBaseScoreVector() {
        try {
            verifyBaseParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        String vector = "";

        if (ACCESS_VECTOR.ID == ACCESS_VECTOR_REQUIRES_LOCAL_ACCESS.ID)
            vector += "AV:L/";
        if (ACCESS_VECTOR.ID == ACCESS_VECTOR_ADJACENT_NETWORK_ACCESSIBLE.ID)
            vector += "AV:A/";
        if (ACCESS_VECTOR.ID == ACCESS_VECTOR_NETWORK_ACCESSIBLE.ID)
            vector += "AV:N/";

        if (ACCESS_COMPLEXITY.ID == ACCESS_COMPLEXITY_LOW.ID)
            vector += "AC:L/";
        if (ACCESS_COMPLEXITY.ID == ACCESS_COMPLEXITY_MEDIUM.ID)
            vector += "AC:M/";
        if (ACCESS_COMPLEXITY.ID == ACCESS_COMPLEXITY_HIGH.ID)
            vector += "AC:H/";

        if (AUTHENTICATION.ID == AUTHENTICATION_REQUIRES_NO_AUTHENTICATION.ID)
            vector += "Au:N/";
        if (AUTHENTICATION.ID == AUTHENTICATION_REQUIRES_SINGLE_INSTANCE.ID)
            vector += "Au:S/";
        if (AUTHENTICATION.ID == AUTHENTICATION_REQUIRES_MULTIPLE_INSTANCES.ID)
            vector += "Au:M/";

        if (CONFIDENTIALITY_IMPACT.ID == CONFIDENTIALITY_IMPACT_NONE.ID)
            vector += "C:N/";
        if (CONFIDENTIALITY_IMPACT.ID == CONFIDENTIALITY_IMPACT_PARTIAL.ID)
            vector += "C:P/";
        if (CONFIDENTIALITY_IMPACT.ID == CONFIDENTIALITY_IMPACT_COMPLETE.ID)
            vector += "C:C/";

        if (INTEGRITY_IMPACT.ID == INTEGRITY_IMPACT_NONE.ID)
            vector += "I:N/";
        if (INTEGRITY_IMPACT.ID == INTEGRITY_IMPACT_PARTIAL.ID)
            vector += "I:P/";
        if (INTEGRITY_IMPACT.ID == INTEGRITY_IMPACT_COMPLETE.ID)
            vector += "I:C/";

        if (AVAILABILITY_IMPACT.ID == AVAILABILITY_IMPACT_NONE.ID)
            vector += "A:N";
        if (AVAILABILITY_IMPACT.ID == AVAILABILITY_IMPACT_PARTIAL.ID)
            vector += "A:P";
        if (AVAILABILITY_IMPACT.ID == AVAILABILITY_IMPACT_COMPLETE.ID)
            vector += "A:C";

        return vector;
    }

    /**
     * Returns a string representation of the temporal vector
     * @return A string representation of the temporal vector
     */
    public String getTemporalVector() {
        try {
            verifyAllParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        String vector = "";

        if (EXPLOITABILITY.ID == EXPLOITABILITY_UNPROVEN.ID)
            vector += "E:U/";
        if (EXPLOITABILITY.ID == EXPLOITABILITY_PROOF_OF_CONCEPT.ID)
            vector += "E:POC/";
        if (EXPLOITABILITY.ID == EXPLOITABILITY_FUNCTIONAL.ID)
            vector += "E:F/";
        if (EXPLOITABILITY.ID == EXPLOITABILITY_HIGH.ID)
            vector += "E:H/";
        if (EXPLOITABILITY.ID == EXPLOITABILITY_NOT_DEFINED.ID)
            vector += "E:ND/";

        if (REMEDIATION_LEVEL.ID == REMEDIATION_LEVEL_OFFICIAL_FIX.ID)
            vector += "RL:OF/";
        if (REMEDIATION_LEVEL.ID == REMEDIATION_LEVEL_TEMPORARY_FIX.ID)
            vector += "RL:TF/";
        if (REMEDIATION_LEVEL.ID == REMEDIATION_LEVEL_WORKAROUND.ID)
            vector += "RL:W/";
        if (REMEDIATION_LEVEL.ID == REMEDIATION_LEVEL_UNAVAILABLE.ID)
            vector += "RL:U/";
        if (REMEDIATION_LEVEL.ID == REMEDIATION_LEVEL_NOT_DEFINED.ID)
            vector += "RL:ND/";

        if (REPORT_CONFIDENCE.ID == REPORT_CONFIDENCE_UNCONFIRMED.ID)
            vector += "RC:UC";
        if (REPORT_CONFIDENCE.ID == REPORT_CONFIDENCE_UNCORROBORATED.ID)
            vector += "RC:UR";
        if (REPORT_CONFIDENCE.ID == REPORT_CONFIDENCE_CONFIRMED.ID)
            vector += "RC:C";
        if (REPORT_CONFIDENCE.ID == REPORT_CONFIDENCE_NOT_DEFINED.ID)
            vector += "RC:ND";

        return vector;
    }

    /**
     * Returns a string representation of the environmental vector
     * @return A string representation of teh environmental vector
     */
    public String getEnviornmentalVector() {
        try {
            verifyAllParameters();
        } catch (IllegalArgumentException e) {
            throw e;
        }

        String vector = "";

        if (COLLATERAL_DAMAGE.ID == COLLATERAL_DAMAGE_NONE.ID)
            vector += "CDP:N/";
        if (COLLATERAL_DAMAGE.ID == COLLATERAL_DAMAGE_LOW.ID)
            vector += "CDP:L/";
        if (COLLATERAL_DAMAGE.ID == COLLATERAL_DAMAGE_LOW_MEDIUM.ID)
            vector += "CDP:LM/";
        if (COLLATERAL_DAMAGE.ID == COLLATERAL_DAMAGE_MEDIUM_HIGH.ID)
            vector += "CDP:MH/";
        if (COLLATERAL_DAMAGE.ID == COLLATERAL_DAMAGE_HIGH.ID)
            vector += "CDP:H/";
        if (COLLATERAL_DAMAGE.ID == COLLATERAL_DAMAGE_NOT_DEFINED.ID)
            vector += "CDP:ND/";

        if (TARGET_DISTRIBUTION.ID == TARGET_DISTRIBUTION_NONE.ID)
            vector += "TD:N/";
        if (TARGET_DISTRIBUTION.ID == TARGET_DISTRIBUTION_LOW.ID)
            vector += "TD:L/";
        if (TARGET_DISTRIBUTION.ID == TARGET_DISTRIBUTION_MEDIUM.ID)
            vector += "TD:M/";
        if (TARGET_DISTRIBUTION.ID == TARGET_DISTRIBUTION_HIGH.ID)
            vector += "TD:H/";
        if (TARGET_DISTRIBUTION.ID == TARGET_DISTRIBUTION_NOT_DEFINED.ID)
            vector += "TD:ND/";

        if (CONFIDENTIALITY_REQUIREMENT.ID == CONFIDENTIALITY_REQUIREMENT_LOW.ID)
            vector += "CR:L/";
        if (CONFIDENTIALITY_REQUIREMENT.ID == CONFIDENTIALITY_REQUIREMENT_MEDIUM.ID)
            vector += "CR:M/";
        if (CONFIDENTIALITY_REQUIREMENT.ID == CONFIDENTIALITY_REQUIREMENT_HIGH.ID)
            vector += "CR:H/";
        if (CONFIDENTIALITY_REQUIREMENT.ID == CONFIDENTIALITY_REQUIREMENT_NOT_DEFINED.ID)
            vector += "CR:ND/";

        if (INTEGRITY_REQUIREMENT.ID == INTEGRITY_REQUIREMENT_LOW.ID)
            vector += "IR:L/";
        if (INTEGRITY_REQUIREMENT.ID == INTEGRITY_REQUIREMENT_MEDIUM.ID)
            vector += "IR:M/";
        if (INTEGRITY_REQUIREMENT.ID == INTEGRITY_REQUIREMENT_HIGH.ID)
            vector += "IR:H/";
        if (INTEGRITY_REQUIREMENT.ID == INTEGRITY_REQUIREMENT_NOT_DEFINED.ID)
            vector += "IR:ND/";

        if (AVAILABILITY_REQUIREMENT.ID == AVAILABILITY_REQUIREMENT_LOW.ID)
            vector += "AR:L";
        if (AVAILABILITY_REQUIREMENT.ID == AVAILABILITY_REQUIREMENT_MEDIUM.ID)
            vector += "AR:M";
        if (AVAILABILITY_REQUIREMENT.ID == AVAILABILITY_REQUIREMENT_HIGH.ID)
            vector += "AR:H";
        if (AVAILABILITY_REQUIREMENT.ID == AVAILABILITY_REQUIREMENT_NOT_DEFINED.ID)
            vector += "AR:ND";

        return vector;
    }
}
