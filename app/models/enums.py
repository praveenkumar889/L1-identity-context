"""
Enumerations for the Identity & Context layer.
===============================================

Canonical enum definitions used across models, services, and API.
"""

from enum import IntEnum, Enum


class ClearanceLevel(IntEnum):
    """Data sensitivity clearance levels.

    Maps to the 5-tier data classification in the Knowledge Graph (L2):
      1 = Public        (facility names, department names)
      2 = Internal      (staff schedules, equipment)
      3 = Confidential  (patient names, MRN, diagnosis codes)
      4 = Highly Conf.  (Aadhaar, DOB, salary, bank accounts)
      5 = Restricted    (psychotherapy notes, substance abuse, HIV)
    """
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    HIGHLY_CONFIDENTIAL = 4
    RESTRICTED = 5


class Domain(str, Enum):
    """Organisational data domains — enforced as isolation boundaries in L6."""
    CLINICAL = "CLINICAL"
    FINANCIAL = "FINANCIAL"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    RESEARCH = "RESEARCH"
    COMPLIANCE = "COMPLIANCE"
    IT_OPERATIONS = "IT_OPERATIONS"


class EmergencyMode(str, Enum):
    """Break-the-Glass (BTG) state."""
    NONE = "NONE"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"


class EmploymentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ON_LEAVE = "ON_LEAVE"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
