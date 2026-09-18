"""
Identity model: who is behind a request, not just which org/API-key.

Tenancy used to stop at organizations + api_keys, so the platform could never
answer "who is using which AI service?" — every call under a shared app/API
key looked identical. ``X-VisorShield-User`` (see auth_middleware) carries the
caller's own identifier (SSO subject, email, employee ID — whatever the
integrating app already has); these tables are what it gets resolved into.
"""
import uuid
from sqlalchemy import Column, String, Boolean, TIMESTAMP, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.database import Base


class Department(Base):
    __tablename__ = "departments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    users = relationship("User", back_populates="department")

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_department_org_name"),)


class Group(Base):
    """A cross-cutting membership (e.g. 'Finance', 'Legal-Reviewers') independent of department."""
    __tablename__ = "groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(150), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_group_org_name"),)


class User(Base):
    """
    A caller identity, auto-provisioned the first time ``X-VisorShield-User``
    is seen for an org. ``external_id`` is whatever the calling app already
    uses (SSO subject, email, employee ID) — VisorShield has no login of its
    own and does not mint or validate these values, only tracks them.
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    external_id = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    department_id = Column(UUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    first_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

    department = relationship("Department", back_populates="users")

    __table_args__ = (UniqueConstraint("org_id", "external_id", name="uq_user_org_external_id"),)


class UserGroupMembership(Base):
    __tablename__ = "user_group_memberships"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    group_id = Column(UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
