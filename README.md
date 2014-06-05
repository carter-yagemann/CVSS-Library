CVSS Library
============

Description
-----------

The goal of this project is to provide a Java class for generating Common
Vulnerability Scoring System (CVSS) scores. This project is based on version
2 of the CVSS standard which can be found online at: http://www.first.org/cvss/cvss-guide .

Status
------

This project is currently open for public use.

Dependencies
------------

This project has no dependencies beyond the standard Java Development Kit (JDK).

Getting Started
---------------

Simply create a new object and assign it values. Values should be assigned using
the constants defined in the class. Note that CVSS scores are broken down into
base score, temporal score and environmental score. The base score is the only
required score while temporal score and environmental score are optional. Therefore,
only the base score variables have to be assigned if you only care about calculating
base scores. More information about the score vectors can be found in the CVSS standard
documentation along with scoring guidelines and other useful information.

Variables
=========

The base score and its variables are the only required variables. However, all 
variables should be set if you want to calculate all three scores.

Assigning Variables
-------------------

Variables should be assigned values using the predefined constants like so:

`cvssElement.setAccessVector(ACCESS_VECTOR_NETWORK_ACCESSIBLE);`

Calculating Scores
==================

Scores can be calculated using the `calculateBaseScore` and `calculateScores` methods.
The `calculateScores` method returns the three scores as doubles in the order Base Score,
Temporal Score, Environmental Score.

Getting String Vectors
======================

It is common in CVSS to include the three vectors used to calculate the scores along
with the scores. These strings can be generated using the `getBaseVector`,
`getTemporalVector`, and `getEnvironmentalVector` methods.
