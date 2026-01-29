BEGIN;

CREATE TABLE IF NOT EXISTS job_queue (
  id BIGSERIAL PRIMARY KEY,
  job_type TEXT NOT NULL,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  priority INT NOT NULL DEFAULT 0,
  run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'new', -- new|running|done|failed
  tries INT NOT NULL DEFAULT 0,
  last_error TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::JSONB,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_job_queue UNIQUE (job_type, platform, program_external_id, payload)
);

CREATE INDEX IF NOT EXISTS idx_job_queue_status
  ON job_queue(status);

CREATE INDEX IF NOT EXISTS idx_job_queue_due
  ON job_queue(status, run_after, priority DESC);

CREATE INDEX IF NOT EXISTS idx_job_queue_program
  ON job_queue(platform, program_external_id);

COMMIT;
