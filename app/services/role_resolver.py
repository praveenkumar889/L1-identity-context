"""
role_resolver.py — Role Inheritance & Clearance Resolution (Strict Reference Alignment)
=====================================================================================

Follows the provided reference samples for Neo4j resolution logic:
- INHERITS_FROM*0.. traversal for effective roles.
- ACCESSES_DOMAIN for domain aggregation.
- BaseRoleResolver abstract pattern.
- User profile lookup for Staff/Doctor labels.
"""

from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from neo4j import GraphDatabase, Driver

from app.models.enums import Domain
from app.config import get_settings

logger = logging.getLogger("l1.role_resolver")

@dataclass
class ResolvedRoles:
    """Consolidated output of role and metadata resolution."""
    direct_roles: list[str]
    effective_roles: list[str]
    domain: Domain
    clearance_level: int
    sensitivity_cap: int
    allowed_domains: list[str] = field(default_factory=list)
    bound_policies: list[str] = field(default_factory=list)
    department: Optional[str] = None
    facility_id: Optional[str] = None

class BaseRoleResolver(ABC):
    """Abstract base class as provided in reference."""
    @abstractmethod
    def resolve(self, direct_roles: List[str]) -> List[str]:
        pass

    @abstractmethod
    def get_role_metadata(self, roles: List[str]) -> Dict:
        pass

class RoleResolver(BaseRoleResolver):
    """
    Authoritative Neo4j Role Resolver.
    Follows provided snippets for labels (Staff/Doctor) and properties (clearance_level).
    """

    def __init__(self, driver: Driver | None = None):
        settings = get_settings()
        if driver:
            self.driver = driver
        else:
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD)
            )
        self.database = settings.NEO4J_DATABASE

    def get_user_profile(self, user_oid: str) -> Dict:
        """From Neo4jUserProfileStore snippet: fetches staff/doctor data.
        Modified to also fetch roles associated with the user.
        """
        query = """
        MATCH (u)
        WHERE (u:Staff OR u:Doctor OR u:User OR u:Person) 
          AND (u.user_id = $uid OR u.oid = $uid OR u.name CONTAINS $uid)
        OPTIONAL MATCH (u)-[:HAS_ROLE]->(r:Role)
        RETURN u.user_id AS user_id,
               u.department AS department,
               u.facility_id AS facility,
               u.clearance_level AS clearance_level,
               u.max_clearance AS max_clearance,
               collect(r.name) AS roles
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, uid=user_oid)
                record = result.single()
                if record:
                    logger.info("Found user profile in Neo4j for %s", user_oid)
                    return {
                        "clearance": record["clearance_level"] or record["max_clearance"],
                        "department": record["department"],
                        "facility": record["facility"],
                        "roles": [r for r in record["roles"] if r]
                    }
                else:
                    logger.warning("No user profile found in Neo4j for %s", user_oid)
        except Exception as e:
            logger.error("Failed to fetch user profile from Neo4j: %s", e)
        return {}

    def resolve(self, direct_roles: List[str]) -> List[str]:
        """From n204j_role_resolver snippet: traverses hierarchy."""
        if not direct_roles:
            return []

        effective_roles = set()
        try:
            with self.driver.session(database=self.database) as session:
                for role_name in direct_roles:
                    # Case-insensitive match using toLower for robustness
                    query = """
                    MATCH (r:Role)
                    WHERE toLower(r.name) = toLower($role_name) AND r.is_active = true
                    OPTIONAL MATCH (r)-[:INHERITS_FROM*0..]->(ancestor:Role)
                    WHERE ancestor.is_active = true
                    RETURN DISTINCT ancestor.name AS role
                    """
                    result = session.run(query, role_name=role_name)
                    found = False
                    for record in result:
                        if record["role"]:
                            effective_roles.add(record["role"])
                            found = True
                    if not found:
                        logger.warning(f"Role '{role_name}' not found in Neo4j or is inactive.")
                        effective_roles.add(role_name)
        except Exception as e:
            logger.error(f"Neo4j traversal failed: {e}")
            effective_roles.update(direct_roles)

        return sorted(list(effective_roles))

    def get_role_metadata(self, roles: List[str]) -> Dict:
        """From n204j_role_resolver snippet: computes clearance and domains."""
        if not roles:
            return {"allowed_domains": [], "max_clearance_level": None}

        allowed_domains = set()
        # Case-insensitive match for metadata
        query = """
        MATCH (r:Role)
        WHERE r.name IN $roles OR ANY(name IN $roles WHERE toLower(r.name) = toLower(name))
        OPTIONAL MATCH (r)-[:ACCESSES_DOMAIN]->(d:Domain)
        RETURN r.level AS level, d.name AS domain
        """
        levels = []
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, roles=roles)
                for record in result:
                    if record["level"] is not None:
                        levels.append(int(record["level"]))
                    if record["domain"]:
                        allowed_domains.add(record["domain"])
        except Exception as e:
            logger.error("Failed to fetch role metadata: %s", e)

        return {
            "allowed_domains": sorted(list(allowed_domains)),
            "max_clearance_level": min(levels) if levels else None
        }

    def full_resolve(self, user_oid: str, jwt_roles: List[str], mfa_verified: bool) -> ResolvedRoles:
        """Orchestrates the individual reference methods.
        
        Resolution logic:
          1. Roles: Union of JWT roles + Direct roles from Neo4j (HAS_ROLE)
          2. Clearance: Profile clearance property > Min role level > Default (5)
          3. Domain: Roles' primary domain > Default (CLINICAL)
        """
        # 1. Fetch User Data from Neo4j
        profile = self.get_user_profile(user_oid)
        
        # 2. Resolve Direct Roles (Merge JWT + Neo4j)
        neo4j_direct_roles = profile.get("roles", [])
        direct_roles = list(set(jwt_roles) | set(neo4j_direct_roles))
        
        logger.info(
            "Resolving roles for %s | jwt_roles=%s neo4j_roles=%s combined=%s", 
            user_oid, jwt_roles, neo4j_direct_roles, direct_roles
        )
        
        if not direct_roles and not profile:
            logger.warning("No roles or profile found for user %s. Using safe defaults.", user_oid)
        
        # 3. Resolve Effective Roles (Traverse Hierarchy)
        effective_roles = self.resolve(direct_roles)
        logger.info("Hierarchy expanded | input=%s effective=%s", direct_roles, effective_roles)
        
        # 4. Resolve Metadata from all roles
        metadata = self.get_role_metadata(effective_roles)
        
        # 5. Final Clearance Logic
        # Priority: explicit user property > role-based min level > default (5)
        clearance = profile.get("clearance")
        role_min_clearance = metadata.get("max_clearance_level")
        
        if clearance is None:
            clearance = role_min_clearance or 5
            logger.debug("Using role-based or default clearance: %s", clearance)
        else:
            logger.debug("Using explicit user-node clearance: %s", clearance)
        
        try:
            clearance = int(clearance)
        except (TypeError, ValueError):
            clearance = 5
            
        logger.info(
            "Clearance determined | user=%s level=%d (profile=%s, role_min=%s)",
            user_oid, clearance, profile.get("clearance"), role_min_clearance
        )
            
        # MFA Sensitivity Cap (M3/M5 Requirement)
        # If not MFA verified, sensitivity_cap is clearance + 1 (lower access)
        sensitivity_cap = clearance + (0 if mfa_verified else 1)
        if sensitivity_cap > 5:
            sensitivity_cap = 5
        
        # 6. Domain Normalization
        allowed_domains = metadata.get("allowed_domains", [])
        primary_domain_str = allowed_domains[0] if allowed_domains else "CLINICAL"
        try:
            domain = Domain(primary_domain_str.upper())
        except:
            domain = Domain.CLINICAL
        
        logger.debug(
            "Full resolution complete | user=%s direct=%s effective=%s clearance=%d domains=%s",
            user_oid, direct_roles, effective_roles, clearance, allowed_domains
        )

        return ResolvedRoles(
            direct_roles=sorted(direct_roles),
            effective_roles=effective_roles,
            domain=domain,
            clearance_level=clearance,
            sensitivity_cap=sensitivity_cap,
            allowed_domains=allowed_domains,
            bound_policies=[],
            department=profile.get("department"),
            facility_id=profile.get("facility")
        )
