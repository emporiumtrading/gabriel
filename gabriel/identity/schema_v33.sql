-- Provider/model selection is part of the durable investigation contract.  A
-- resumed job must not silently switch providers or model families.
ALTER TABLE gabriel_identity.specialist_agent_jobs
    ADD COLUMN provider text NOT NULL DEFAULT 'openrouter'
        CHECK (provider IN ('openrouter','deepinfra'));

ALTER TABLE gabriel_identity.hermes_runs
    ADD COLUMN provider text NOT NULL DEFAULT 'openrouter'
        CHECK (provider IN ('openrouter','deepinfra')),
    ADD COLUMN specialist_provider text NOT NULL DEFAULT 'openrouter'
        CHECK (specialist_provider IN ('openrouter','deepinfra'));

REVOKE ALL ON gabriel_identity.specialist_agent_jobs,gabriel_identity.hermes_runs FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.specialist_agent_jobs,gabriel_identity.hermes_runs TO gabriel_identity_app;
