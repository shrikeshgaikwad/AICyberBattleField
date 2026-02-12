-- AI Cyber Battlefield Database Initialization Script
-- This script initializes the PostgreSQL database with required tables and settings

-- Create schemas
CREATE SCHEMA IF NOT EXISTS cyber_data;
CREATE SCHEMA IF NOT EXISTS logs;

-- =============================================
-- Scan Results Table
-- =============================================
CREATE TABLE IF NOT EXISTS cyber_data.scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL DEFAULT gen_random_uuid(),
    target_host VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'in_progress',
    results JSONB,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scan_id ON cyber_data.scan_results(scan_id);
CREATE INDEX idx_target_host ON cyber_data.scan_results(target_host);
CREATE INDEX idx_scan_type ON cyber_data.scan_results(scan_type);
CREATE INDEX idx_created_at ON cyber_data.scan_results(created_at);

-- =============================================
-- Vulnerability Findings Table
-- =============================================
CREATE TABLE IF NOT EXISTS cyber_data.vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    severity VARCHAR(20) NOT NULL,
    cve_id VARCHAR(50),
    description TEXT,
    affected_service VARCHAR(255),
    remediation TEXT,
    confidence NUMERIC(3,2),
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES cyber_data.scan_results(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_scan_vuln ON cyber_data.vulnerabilities(scan_id);
CREATE INDEX idx_severity ON cyber_data.vulnerabilities(severity);
CREATE INDEX idx_cve_id ON cyber_data.vulnerabilities(cve_id);

-- =============================================
-- Agent Actions Log Table
-- =============================================
CREATE TABLE IF NOT EXISTS logs.agent_actions (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    action_description TEXT,
    parameters JSONB,
    result JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER
);

CREATE INDEX idx_agent_id ON logs.agent_actions(agent_id);
CREATE INDEX idx_action_type ON logs.agent_actions(action_type);
CREATE INDEX idx_executed_at ON logs.agent_actions(executed_at);
CREATE INDEX idx_status ON logs.agent_actions(status);

-- =============================================
-- AI Decisions Log Table
-- =============================================
CREATE TABLE IF NOT EXISTS logs.ai_decisions (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(100) NOT NULL,
    context TEXT,
    decision TEXT NOT NULL,
    reasoning TEXT,
    confidence NUMERIC(3,2),
    outcome VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ai_agent ON logs.ai_decisions(agent_id);
CREATE INDEX idx_ai_created ON logs.ai_decisions(created_at);

-- =============================================
-- System Events Table
-- =============================================
CREATE TABLE IF NOT EXISTS logs.system_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT,
    metadata JSONB,
    resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_event_type ON logs.system_events(event_type);
CREATE INDEX idx_severity ON logs.system_events(severity);
CREATE INDEX idx_resolved ON logs.system_events(resolved);

-- =============================================
-- Views for common queries
-- =============================================
CREATE OR REPLACE VIEW cyber_data.latest_scans AS
SELECT 
    scan_id,
    target_host,
    scan_type,
    status,
    started_at,
    completed_at,
    EXTRACT(EPOCH FROM (completed_at - started_at))::INT as duration_seconds
FROM cyber_data.scan_results
ORDER BY created_at DESC
LIMIT 100;

CREATE OR REPLACE VIEW cyber_data.vulnerability_summary AS
SELECT 
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT scan_id) as affected_scans
FROM cyber_data.vulnerabilities
GROUP BY severity;

-- =============================================
-- Grant permissions
-- =============================================
GRANT USAGE ON SCHEMA cyber_data TO cyber_user;
GRANT USAGE ON SCHEMA logs TO cyber_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA cyber_data TO cyber_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA logs TO cyber_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA cyber_data TO cyber_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA logs TO cyber_user;

-- =============================================
-- Comments for documentation
-- =============================================
COMMENT ON SCHEMA cyber_data IS 'Stores scan results and vulnerability data';
COMMENT ON SCHEMA logs IS 'Stores operational logs and audit trails';
COMMENT ON TABLE cyber_data.scan_results IS 'Contains results from security scans';
COMMENT ON TABLE cyber_data.vulnerabilities IS 'Contains identified vulnerabilities from scans';
COMMENT ON TABLE logs.agent_actions IS 'Audit log of all agent actions performed';
COMMENT ON TABLE logs.ai_decisions IS 'Log of AI decision-making process';
COMMENT ON TABLE logs.system_events IS 'System-wide events and alerts';
