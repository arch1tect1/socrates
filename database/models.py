"""SQLAlchemy ORM models for SOCrates bot."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    telegram_user_id = Column(BigInteger, unique=True, nullable=False, index=True)
    username = Column(String(255), nullable=True)
    first_name = Column(String(255), nullable=True)
    last_name = Column(String(255), nullable=True)
    language_code = Column(String(10), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_active_at = Column(DateTime(timezone=True), server_default=func.now())

    profiles = relationship("OrgProfileDB", back_populates="user", cascade="all, delete-orphan")
    analyses = relationship("AnalysisDB", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("SessionDB", back_populates="user", cascade="all, delete-orphan")


class OrgProfileDB(Base):
    __tablename__ = "org_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    industry = Column(String(100), nullable=False, server_default="")
    org_name = Column(String(255), nullable=False, server_default="")
    cloud_providers = Column(JSON, nullable=True)
    tor_policy = Column(String(50), nullable=False, server_default="")
    authorized_vpns = Column(JSON, nullable=True)
    unknown_vpn_policy = Column(String(50), nullable=False, server_default="")
    never_block_ips = Column(JSON, nullable=True)
    own_infrastructure = Column(JSON, nullable=True)
    security_stack = Column(String(500), nullable=False, server_default="")
    custom_policies = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("UserDB", back_populates="profiles")


class AnalysisDB(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    decision_id = Column(String(32), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False, server_default="")
    ioc_value = Column(String(500), nullable=False, server_default="")
    enrichment_data = Column(JSON, nullable=True)
    ambiguity_flags = Column(JSON, nullable=True)
    ai_verdict = Column(String(100), nullable=False, server_default="")
    ai_severity = Column(String(100), nullable=False, server_default="")
    ai_confidence = Column(String(100), nullable=False, server_default="")
    ai_recommended_action = Column(String(500), nullable=False, server_default="")
    full_response = Column(Text, nullable=False, server_default="")
    analyst_feedback = Column(String(50), nullable=False, server_default="")
    analyst_action_taken = Column(String(500), nullable=False, server_default="")
    analyst_note = Column(Text, nullable=False, server_default="")
    resolution = Column(String(200), nullable=False, server_default="")
    tags = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("UserDB", back_populates="analyses")


class SessionDB(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_type = Column(String(50), nullable=False)
    state = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("UserDB", back_populates="sessions")
