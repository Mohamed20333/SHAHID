-- =====================================================================
-- Shahid Platform — Core Relational Schema (Phase 1 of 5)
-- Target: PostgreSQL 15+
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

CREATE TYPE user_role AS ENUM ('student', 'professor', 'dept_admin', 'university_admin', 'platform_admin');
CREATE TYPE session_status AS ENUM ('scheduled', 'active', 'closed', 'compliance_degraded');
CREATE TYPE attendance_outcome AS ENUM ('present', 'absent', 'present_pending_review');
CREATE TYPE escalation_status AS ENUM ('not_triggered', 'pending', 'passed', 'failed', 'expired');
CREATE TYPE hisba_case_type AS ENUM ('complaint', 'appeal', 'sick_leave', 'faq_escalation', 'feedback_survey');
CREATE TYPE hisba_case_status AS ENUM ('open', 'in_review', 'resolved', 'closed_cop_issued');

CREATE TABLE universities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    country_code CHAR(2) NOT NULL,
    ukvi_sponsor BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    university_id UUID NOT NULL REFERENCES universities(id) ON DELETE RESTRICT,
    role user_role NOT NULL,
    full_name TEXT NOT NULL,
    email CITEXT NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (university_id, email)
);

CREATE INDEX idx_users_university ON users(university_id);

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_enrollment_key_hash TEXT NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    is_primary BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (device_enrollment_key_hash)
);

CREATE INDEX idx_devices_user ON devices(user_id);

CREATE TABLE courses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    university_id UUID NOT NULL REFERENCES universities(id) ON DELETE RESTRICT,
    code TEXT NOT NULL,
    title TEXT NOT NULL,
    UNIQUE (university_id, code)
);

CREATE TABLE sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    instructor_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    term TEXT NOT NULL
);

CREATE INDEX idx_sections_course ON sections(course_id);
CREATE INDEX idx_sections_instructor ON sections(instructor_id);

CREATE TABLE enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    section_id UUID NOT NULL REFERENCES sections(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (section_id, student_id)
);

CREATE TABLE class_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    section_id UUID NOT NULL REFERENCES sections(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    status session_status NOT NULL DEFAULT 'scheduled',
    epoch_seconds SMALLINT NOT NULL DEFAULT 25 CHECK (epoch_seconds BETWEEN 15 AND 60)
);

CREATE INDEX idx_sessions_section ON class_sessions(section_id, started_at);

CREATE TABLE witness_observations (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
    observer_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    observed_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    epoch_index INTEGER NOT NULL,
    rssi SMALLINT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature TEXT NOT NULL,
    CHECK (observer_device_id <> observed_device_id)
);

CREATE INDEX idx_witness_session_observed ON witness_observations(session_id, observed_device_id);
CREATE INDEX idx_witness_pair ON witness_observations(observer_device_id, observed_device_id);

CREATE TABLE attendance_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    outcome attendance_outcome NOT NULL,
    witness_count SMALLINT NOT NULL DEFAULT 0,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, student_id)
);

CREATE INDEX idx_attendance_student ON attendance_records(student_id, decided_at);

CREATE TABLE pair_stats (
    device_a_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    device_b_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sessions_observed INTEGER NOT NULL DEFAULT 0,
    co_occurrence_rate NUMERIC(4,3) NOT NULL DEFAULT 0 CHECK (co_occurrence_rate BETWEEN 0 AND 1),
    variance_score NUMERIC(4,3) NOT NULL DEFAULT 1 CHECK (variance_score BETWEEN 0 AND 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_a_id, device_b_id),
    CHECK (device_a_id < device_b_id)
);

CREATE TABLE session_engagement_scores (
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
    score NUMERIC(4,3) NOT NULL CHECK (score BETWEEN 0 AND 1),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (student_id, session_id)
);

CREATE TABLE liveness_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
    sent_at TIMESTAMPTZ NOT NULL,
    answered_at TIMESTAMPTZ,
    passed BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (student_id, session_id)
);

CREATE TABLE risk_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    risk_score NUMERIC(4,3) NOT NULL CHECK (risk_score BETWEEN 0 AND 1),
    reasons JSONB NOT NULL DEFAULT '[]',
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, student_id)
);

CREATE INDEX idx_risk_student ON risk_assessments(student_id, computed_at);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by UUID REFERENCES refresh_tokens(id)
);

CREATE INDEX idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);

CREATE TABLE escalation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    risk_assessment_id UUID NOT NULL UNIQUE REFERENCES risk_assessments(id) ON DELETE CASCADE,
    status escalation_status NOT NULL DEFAULT 'not_triggered',
    challenge_type TEXT,
    requested_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    liveness_passed BOOLEAN
);

CREATE TABLE pulse_questions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES class_sessions(id) ON DELETE CASCADE,
    prompt TEXT NOT NULL,
    generated_by TEXT NOT NULL DEFAULT 'llm_assisted',
    reviewed_by UUID REFERENCES users(id),
    scheduled_offset_hours INTEGER NOT NULL
);

CREATE INDEX idx_pulse_questions_session ON pulse_questions(session_id);

CREATE TABLE pulse_responses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    question_id UUID NOT NULL REFERENCES pulse_questions(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_correct BOOLEAN NOT NULL,
    answered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (question_id, student_id)
);

CREATE TABLE engagement_scores (
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    section_id UUID NOT NULL REFERENCES sections(id) ON DELETE CASCADE,
    score NUMERIC(4,3) NOT NULL CHECK (score BETWEEN 0 AND 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (student_id, section_id)
);

CREATE TABLE hisba_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    university_id UUID NOT NULL REFERENCES universities(id) ON DELETE RESTRICT,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    case_type hisba_case_type NOT NULL,
    status hisba_case_status NOT NULL DEFAULT 'open',
    sla_due_at TIMESTAMPTZ NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ
);

CREATE INDEX idx_hisba_university_status ON hisba_cases(university_id, status);
CREATE INDEX idx_hisba_student ON hisba_cases(student_id);

CREATE TABLE hisba_case_events (
    id BIGSERIAL PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES hisba_cases(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES users(id),
    event_type TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_hisba_events_case ON hisba_case_events(case_id, occurred_at);

CREATE TABLE isnad_verified_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_platform TEXT NOT NULL,
    external_ref TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verification_signature TEXT NOT NULL,
    UNIQUE (source_platform, external_ref)
);

CREATE INDEX idx_isnad_credentials_student ON isnad_verified_credentials(student_id);

CREATE TABLE isnad_skill_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    skill_label TEXT NOT NULL,
    mastery_level NUMERIC(4,3) NOT NULL CHECK (mastery_level BETWEEN 0 AND 1),
    contributing_sources JSONB NOT NULL DEFAULT '[]',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (student_id, skill_label)
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    university_id UUID REFERENCES universities(id),
    actor_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    target_table TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason_code TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_target ON audit_log(target_table, target_id);
CREATE INDEX idx_audit_actor ON audit_log(actor_id, occurred_at);