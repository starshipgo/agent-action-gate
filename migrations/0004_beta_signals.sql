-- Aggregate product signals only: no tenant, principal, tool arguments, source,
-- credentials, IP address, or personal data may enter this table.
CREATE TABLE product_event_counters (
  event_name TEXT NOT NULL CHECK (event_name IN (
    'demo_scenario_run', 'developer_quickstart_view', 'api_key_created',
    'first_evaluation', 'first_approval_created', 'first_approval_consumed'
  )),
  day_utc TEXT NOT NULL CHECK (day_utc GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
  total INTEGER NOT NULL CHECK (total >= 0),
  PRIMARY KEY (event_name, day_utc)
) STRICT;

CREATE TRIGGER product_api_key_created AFTER INSERT ON api_keys
BEGIN
  INSERT INTO product_event_counters VALUES ('api_key_created', date(NEW.created_at, 'unixepoch'), 1)
  ON CONFLICT(event_name, day_utc) DO UPDATE SET total = total + 1;
END;

CREATE TRIGGER product_first_evaluation AFTER INSERT ON audit_events
WHEN NEW.event_type = 'EVALUATED' AND
  (SELECT count(*) FROM audit_events WHERE principal_id = NEW.principal_id AND event_type = 'EVALUATED') = 1
BEGIN
  INSERT INTO product_event_counters VALUES ('first_evaluation', date(NEW.created_at, 'unixepoch'), 1)
  ON CONFLICT(event_name, day_utc) DO UPDATE SET total = total + 1;
END;

CREATE TRIGGER product_first_approval_created AFTER INSERT ON approval_requests
WHEN (SELECT count(*) FROM approval_requests WHERE principal_id = NEW.principal_id) = 1
BEGIN
  INSERT INTO product_event_counters VALUES ('first_approval_created', date(NEW.created_at, 'unixepoch'), 1)
  ON CONFLICT(event_name, day_utc) DO UPDATE SET total = total + 1;
END;

CREATE TRIGGER product_first_approval_consumed AFTER UPDATE OF status ON approval_requests
WHEN OLD.status <> 'CONSUMED' AND NEW.status = 'CONSUMED' AND
  (SELECT count(*) FROM approval_requests WHERE principal_id = NEW.principal_id AND status = 'CONSUMED') = 1
BEGIN
  INSERT INTO product_event_counters VALUES ('first_approval_consumed', date(NEW.consumed_at, 'unixepoch'), 1)
  ON CONFLICT(event_name, day_utc) DO UPDATE SET total = total + 1;
END;

-- Only the four consented beta-interest fields are retained. No telemetry
-- identifier, IP, user agent, email status, or marketing history.
CREATE TABLE beta_interest (
  email TEXT PRIMARY KEY NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
  intended_integration TEXT NOT NULL CHECK (intended_integration IN ('MCP', 'Dify', 'custom_agent', 'other')),
  approximate_monthly_tool_calls TEXT NOT NULL CHECK (approximate_monthly_tool_calls IN ('under_1k', '1k_to_10k', '10k_to_100k', 'over_100k')),
  created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;
