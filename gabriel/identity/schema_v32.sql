ALTER TABLE gabriel_identity.model_price_quotes
    DROP CONSTRAINT IF EXISTS model_price_quotes_provider_check,
    ADD CONSTRAINT model_price_quotes_provider_check
        CHECK (provider IN ('openrouter','deepinfra','nvidia'));

ALTER TABLE gabriel_identity.provider_onboarding_checks
    DROP CONSTRAINT IF EXISTS provider_onboarding_checks_provider_check,
    DROP CONSTRAINT IF EXISTS provider_onboarding_checks_status_check,
    DROP CONSTRAINT IF EXISTS provider_onboarding_checks_check,
    ADD CONSTRAINT provider_onboarding_checks_provider_check
        CHECK (provider IN ('openrouter','deepinfra','nvidia')),
    ADD CONSTRAINT provider_onboarding_checks_status_check
        CHECK (status IN ('funding_verified','inference_verified','validation_pending')),
    ADD CONSTRAINT provider_onboarding_checks_check CHECK (
        (provider='openrouter' AND status='funding_verified'
            AND account_available_microusd IS NOT NULL AND account_available_microusd>=18000000
            AND key_available_microusd IS NOT NULL AND key_available_microusd>=18000000)
        OR (provider='deepinfra' AND status='inference_verified'
            AND account_available_microusd IS NULL AND key_available_microusd IS NULL)
        OR (provider='nvidia' AND status='validation_pending'
            AND account_available_microusd IS NULL AND key_available_microusd IS NULL)
    );

ALTER TABLE gabriel_identity.personal_provider_secrets
    DROP CONSTRAINT IF EXISTS personal_provider_secrets_provider_check,
    ADD CONSTRAINT personal_provider_secrets_provider_check
        CHECK (provider IN ('openrouter','deepinfra'));
