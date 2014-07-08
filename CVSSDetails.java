/**
 * CVSS Details - Common Vulnerability Scoring System detail class (CVSSDetails.java)
 * Copyright (c) 2014  Carter Yagemann
 *
 *
 * This is a simple object for storing detailed information on the parameters used to calculate
 * CVSS scores.
 *
 * This class is based on version 2 of the CVSS standard. More information can be found at:
 * http://www.first.org/cvss/cvss-guide .
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.yagemann.cvss;

public class CVSSDetails {

    public final String ACCESS_VECTOR_NAME = "Access Vector (AV)";
    public final String ACCESS_VECTOR_DESCRIPTION =
            "This metric reflects how the vulnerability is exploited.";
    public final String ACCESS_VECTOR_SCORING_CRITERIA =
            "Local (L): A vulnerability exploitable with only local access requires the attacker " +
                    "to have either physical access to the vulnerable system or a local (shell) " +
                    "account. Examples of locally exploitable vulnerabilities are peripheral " +
                    "attacks such as Firewire/USB DMA attacks, and local privilege escalations " +
                    "(e.g., sudo).\n\n" +
                    "Adjacent Network (A): A vulnerability exploitable with adjacent network " +
                    "access requires the attacker to have access to either the broadcast or " +
                    "collision domain of the vulnerable software.  Examples of local networks " +
                    "include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet " +
                    "segment.\n\n" +
                    "Network (N): A vulnerability exploitable with network access means the " +
                    "vulnerable software is bound to the network stack and the attacker does not " +
                    "require local network access or local access.  Such a vulnerability is " +
                    "often termed \"remotely exploitable\".  An example of a network attack is " +
                    "an RPC buffer overflow.";

    public final String ACCESS_COMPLEXITY_NAME = "Access Complexity (AC)";
    public final String ACCESS_COMPLEXITY_DESCRIPTION =
            "This metric measures the complexity of the attack required to exploit the " +
                    "vulnerability once an attacker has gained access to the target system.";
    public final String ACCESS_COMPLEXITY_SCORING_CRITERIA =
            "High (H): Specialized access conditions exist. For example:\n\n" +
                    "In most configurations, the attacking party must already have elevated " +
                    "privileges or spoof additional systems in addition to the attacking system " +
                    "(e.g., DNS hijacking).\n\n" +
                    "The attack depends on social engineering methods that would be easily " +
                    "detected by knowledgeable people. For example, the victim must perform " +
                    "several suspicious or atypical actions.\n\n" +
                    "The vulnerable configuration is seen very rarely in practice.\n\n" +
                    "If a race condition exists, the window is very narrow.\n\n" +
                    "Medium (M): The access conditions are somewhat specialized; the following " +
                    "are examples:\n\n" +
                    "The attacking party is limited to a group of systems or users at some " +
                    "level of authorization, possibly untrusted.\n\n" +
                    "Some information must be gathered before a successful attack can be " +
                    "launched.\n\n" +
                    "The affected configuration is non-default, and is not commonly " +
                    "configured (e.g., a vulnerability present when a server performs user " +
                    "account authentication via a specific scheme, but not present for another " +
                    "authentication scheme).\n\n" +
                    "The attack requires a small amount of social engineering that might " +
                    "occasionally fool cautious users (e.g., phishing attacks that modify a web " +
                    "browsers status bar to show a false link, having to be on someones buddy " +
                    "list before sending an IM exploit).\n\n" +
                    "Low (L): Specialized access conditions or extenuating circumstances do not " +
                    "exist. The following are examples:\n\n" +
                    "The affected product typically requires access to a wide range of " +
                    "systems and users, possibly anonymous and untrusted (e.g., Internet-facing " +
                    "web or mail server).\n\n" +
                    "The affected configuration is default or ubiquitous.\n\n" +
                    "The attack can be performed manually and requires little skill or " +
                    "additional information gathering.\n\n" +
                    "The race condition is a lazy one (i.e., it is technically a race but " +
                    "easily winnable).";

    public final String AUTHENTICATION_NAME = "Authentication (Au)";
    public final String AUTHENTICATION_DESCRIPTION =
            "This metric measures the number of times an attacker must authenticate to a target " +
                    "in order to exploit a vulnerability. This metric does not gauge the " +
                    "strength or complexity of the authentication process, only that an attacker " +
                    "is required to provide credentials before an exploit may occur.";
    public final String AUTHENTICATION_SCORING_CRITERIA =
            "Multiple (M): Exploiting the vulnerability requires that the attacker authenticate " +
                    "two or more times, even if the same credentials are used each time. An " +
                    "example is an attacker authenticating to an operating system in addition to " +
                    "providing credentials to access an application hosted on that system.\n\n" +
                    "Single (S): The vulnerability requires an attacker to be logged into the " +
                    "system (such as at a command line or via a desktop session or web " +
                    "interface).\n\n" +
                    "None (N): Authentication is not required to exploit the vulnerability.";

    public final String CONFIDENTIALITY_IMPACT_NAME = "Confidentiality Impact (C)";
    public final String CONFIDENTIALITY_IMPACT_DESCRIPTION =
            "This metric measures the impact on confidentiality of a successfully exploited " +
                    "vulnerability. Confidentiality refers to limiting information access and " +
                    "disclosure to only authorized users, as well as preventing access by, or " +
                    "disclosure to, unauthorized ones.";
    public final String CONFIDENTIALITY_IMPACT_SCORING_CRITERIA =
            "None (N): There is no impact to the confidentiality of the system.\n\n" +
                    "Partial (P): There is considerable informational disclosure. Access to some " +
                    "system files is possible, but the attacker does not have control over what " +
                    "is obtained, or the scope of the loss is constrained. An example is a " +
                    "vulnerability that divulges only certain tables in a database.\n\n" +
                    "Complete (C): There is total information disclosure, resulting in all " +
                    "system files being revealed. The attacker is able to read all of the " +
                    "system's data (memory, files, etc.)";

    public final String INTEGRITY_IMPACT_NAME = "Integrity Impact (I)";
    public final String INTEGRITY_IMPACT_DESCRIPTION =
            "This metric measures the impact to integrity of a successfully exploited " +
                    "vulnerability. Integrity refers to the trustworthiness and guaranteed " +
                    "veracity of information.";
    public final String INTEGRITY_IMPACT_SCORING_CRITERIA =
            "None (N): There is no impact to the integrity of the system.\n\n" +
                    "Partial (P): Modification of some system files or information is possible, " +
                    "but the attacker does not have control over what can be modified, or the " +
                    "scope of what the attacker can affect is limited. For example, system or " +
                    "application files may be overwritten or modified, but either the attacker " +
                    "has no control over which files are affected or the attacker can modify " +
                    "files within only a limited context or scope.\n\n" +
                    "Complete (C): There is a total compromise of system integrity. There is a " +
                    "complete loss of system protection, resulting in the entire system being " +
                    "compromised. The attacker is able to modify any files on the target system.";

    public final String AVAILABILITY_IMPACT_NAME = "Availability Impact (A)";
    public final String AVAILABILITY_IMPACT_DESCRIPTION =
            "This metric measures the impact to availability of a successfully exploited " +
                    "vulnerability. Availability refers to the accessibility of information " +
                    "resources.";
    public final String AVAILABILITY_IMPACT_SCORING_CRITERIA =
            "None (N): There is no impact to the availability of the system.\n\n" +
                    "Partial (P): There is reduced performance or interruptions in resource " +
                    "availability. An example is a network-based flood attack that permits a " +
                    "limited number of successful connections to an Internet service.\n\n" +
                    "Complete (C): There is a total shutdown of the affected resource. The " +
                    "attacker can render the resource completely unavailable.";

    public final String EXPLOITABILITY_NAME = "Exploitability (E)";
    public final String EXPLOITABILITY_DESCRIPTION =
            "This metric measures the current state of exploit techniques or code availability. " +
                    "Public availability of easy-to-use exploit code increases the number of " +
                    "potential attackers by including those who are unskilled, thereby " +
                    "increasing the severity of the vulnerability.";
    public final String EXPLOITABILITY_SCORING_CRITERIA =
            "Unproven (U): No exploit code is available, or an exploit is entirely " +
                    "theoretical.\n\n" +
                    "Proof-of-Concept (POC): Proof-of-concept exploit code or an attack " +
                    "demonstration that is not practical for most systems is available. The code " +
                    "or technique is not functional in all situations and may require " +
                    "substantial modification by a skilled attacker.\n\n" +
                    "Functional (F): Functional exploit code is available. The code works in " +
                    "most situations where the vulnerability exists.\n\n" +
                    "High (H): Either the vulnerability is exploitable by functional mobile " +
                    "autonomous code, or no exploit is required (manual trigger) and details " +
                    "are widely available. The code works in every situation, or is actively " +
                    "being delivered via a mobile autonomous agent (such as a worm or virus).\n\n" +
                    "Not Defined (ND): Assigning this value to the metric will not influence " +
                    "the score. It is a signal to the equation to skip this metric.";

    public final String REMEDIATION_LEVEL_NAME = "Remediation Level (RL)";
    public final String REMEDIATION_LEVEL_DESCRIPTION =
            "The remediation level of a vulnerability is an important factor for prioritization. " +
                    "The typical vulnerability is unpatched when initially published. " +
                    "Workarounds or hotfixes may offer interim remediation until an official " +
                    "patch or upgrade is issued. Each of these respective stages adjusts the " +
                    "temporal score downwards, reflecting the decreasing urgency as remediation " +
                    "becomes final.";
    public final String REMEDIATION_LEVEL_SCORING_CRITERIA =
            "Official Fix (OF): A complete vendor solution is available. Either the vendor has " +
                    "issued an official patch, or an upgrade is available.\n\n" +
                    "Temporary Fix (TF): There is an official but temporary fix available. This " +
                    "includes instances where the vendor issues a temporary hotfix, tool, or " +
                    "workaround.\n\n" +
                    "Workaround (W): There is an unofficial, non-vendor solution available. In " +
                    "some cases, users of the affected technology will create a patch of their " +
                    "own or provide steps to work around or otherwise mitigate the " +
                    "vulnerability.\n\n" +
                    "Unavailable (U): There is either no solution available or it is impossible " +
                    "to apply.\n\n" +
                    "Not Defined (ND): Assigning this value to the metric will not influence " +
                    "the score. It is a signal to the equation to skip this metric.";

    public final String REPORT_CONFIDENCE_NAME = "Report Confidence (RC)";
    public final String REPORT_CONFIDENCE_DESCRIPTION =
            "This metric measures the degree of confidence in the existence of the vulnerability " +
                    "and the credibility of the known technical details. Sometimes, only the " +
                    "existence of vulnerabilities are publicized, but without specific details. " +
                    "The vulnerability may later be corroborated and then confirmed through " +
                    "acknowledgement by the author or vendor of the affected technology. The " +
                    "urgency of a vulnerability is higher when a vulnerability is known to exist " +
                    "with certainty.";
    public final String REPORT_CONFIDENCE_SCORING_CRITERIA =
            "Unconfirmed (UC): There is a single unconfirmed source or possibly multiple " +
                    "conflicting reports. There is little confidence in the validity of the " +
                    "reports. An example is a rumor that surfaces from the hacker " +
                    "underground.\n\n" +
                    "Uncorroborated (UR): There are multiple non-official sources, possibly " +
                    "including independent security companies or research organizations. At this " +
                    "point there may be conflicting technical details or some other lingering " +
                    "ambiguity.\n\n" +
                    "Confirmed (C): The vulnerability has been acknowledged by the vendor or " +
                    "author of the affected technology. The vulnerability may also be Confirmed " +
                    "when its existence is confirmed from an external event such as publication " +
                    "of functional or proof-of-concept exploit code or widespread " +
                    "exploitation.\n\n" +
                    "Not Defined (ND): Assigning this value to the metric will not influence the " +
                    "score. It is a signal to the equation to skip this metric.";

    public final String COLLATERAL_DAMAGE_POTENTIAL_NAME = "Collateral Damage Potential (CDP)";
    public final String COLLATERAL_DAMAGE_POTENTIAL_DESCRIPTION =
            "This metric measures the potential for loss of life or physical assets through " +
                    "damage or theft of property or equipment.  The metric may also measure " +
                    "economic loss of productivity or revenue.";
    public final String COLLATERAL_DAMAGE_POTENTIAL_SCORING_CRITERIA =
            "None (N): There is no potential for loss of life, physical assets, productivity or " +
                    "revenue.\n\n" +
                    "Low (L): A successful exploit of this vulnerability may result in slight " +
                    "physical or property damage. Or, there may be a slight loss of revenue or " +
                    "productivity to the organization.\n\n" +
                    "Low-Medium (LM): A successful exploit of this vulnerability may result in " +
                    "moderate physical or property damage. Or, there may be a moderate loss of " +
                    "revenue or productivity to the organization.\n\n" +
                    "Medium-High (MH): A successful exploit of this vulnerability may result in " +
                    "significant physical or property damage or loss. Or, there may be a " +
                    "significant loss of revenue or productivity.\n\n" +
                    "High (H): A successful exploit of this vulnerability may result in " +
                    "catastrophic physical or property damage and loss. Or, there may be a " +
                    "catastrophic loss of revenue or productivity.\n\n" +
                    "Not Defined (ND): Assigning this value to the metric will not influence the " +
                    "score. It is a signal to the equation to skip this metric.";

    public final String TARGET_DISTRIBUTION_NAME = "Target Distribution (TD)";
    public final String TARGET_DISTRIBUTION_DESCRIPTION =
            "This metric measures the proportion of vulnerable systems. It is meant as an " +
                    "environment-specific indicator in order to approximate the percentage of " +
                    "systems that could be affected by the vulnerability.";
    public final String TARGET_DISTRIBUTION_SCORING_CRITERIA =
            "None (N): No target systems exist, or targets are so highly specialized that they " +
                    "only exist in a laboratory setting. Effectively 0% of the environment is at " +
                    "risk.\n\n" +
                    "Low (L): Targets exist inside the environment, but on a small scale. " +
                    "Between 1% - 25% of the total environment is at risk.\n\n" +
                    "Medium (M): Targets exist inside the environment, but on a medium scale. " +
                    "Between 26% - 75% of the total environment is at risk.\n\n" +
                    "High (H): Targets exist inside the environment on a considerable scale. " +
                    "Between 76% - 100% of the total environment is considered at risk.\n\n" +
                    "Not Defined (ND): Assigning this value to the metric will not influence the " +
                    "score. It is a signal to the equation to skip this metric.";

    // CR, IR and AR share the same description and scoring criteria
    private final String SECURITY_REQUIREMENTS_DESCRIPTION =
            "These metrics enable the analyst to customize the CVSS score depending on the " +
                    "importance of the affected IT asset to a users organization, measured in " +
                    "terms of confidentiality, integrity, and availability.";
    private final String SECURITY_REQUIREMENTS_SCORING_CRITERIA =
            "Low (L): Loss of this characteristic is likely to have " +
                    "only a limited adverse effect on the organization or individuals associated " +
                    "with the organization (e.g., employees, customers).\n\n" +
                    "Medium (M): Loss of this characteristic is likely " +
                    "to have a serious adverse effect on the organization or individuals " +
                    "associated with the organization (e.g., employees, customers).\n\n" +
                    "High (H): Loss of this characteristic is likely to " +
                    "have a catastrophic adverse effect on the organization or individuals " +
                    "associated with the organization (e.g., employees, customers).\n\n" +
                    "Not Defined (ND): Assigning this value to the metric will not influence the " +
                    "score. It is a signal to the equation to skip this metric.";

    public final String CONFIDENTIALITY_REQUIREMENT_NAME = "Confidentiality Requirement (CR)";
    public final String CONFIDENTIALITY_REQUIREMENT_DESCRIPTION =
            SECURITY_REQUIREMENTS_DESCRIPTION;
    public final String CONFIDENTIALITY_REQUIREMENT_SCORING_CRITERIA =
            SECURITY_REQUIREMENTS_SCORING_CRITERIA;

    public final String INTEGRITY_REQUIREMENT_NAME = "Integrity Requirement (IR)";
    public final String INTEGRITY_REQUIREMENT_DESCRIPTION =
            SECURITY_REQUIREMENTS_DESCRIPTION;
    public final String INTEGRITY_REQUIREMENT_SCORING_CRITERIA =
            SECURITY_REQUIREMENTS_SCORING_CRITERIA;

    public final String AVAILABILITY_REQUIREMENT_NAME = "Availability Requirement (AR)";
    public final String AVAILABILITY_REQUIREMENT_DESCRIPTION =
            SECURITY_REQUIREMENTS_DESCRIPTION;
    public final String AVAILABILITY_REQUIREMENT_SCORING_CRITERIA =
            SECURITY_REQUIREMENTS_SCORING_CRITERIA;
}
