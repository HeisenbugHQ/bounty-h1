BEGIN;

CREATE TABLE IF NOT EXISTS task_queue (
  id BIGSERIAL PRIMARY KEY,
  platform TEXT NOT NULL,
  program_external_id TEXT NOT NULL,
  task_type TEXT NOT NULL,
  priority INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new', -- new|running|done|failed
  tries INT NOT NULL DEFAULT 0,
  last_error TEXT,
  run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_task_queue_status
  ON task_queue(status);

CREATE INDEX IF NOT EXISTS idx_task_queue_due
  ON task_queue(status, run_after, priority DESC);

CREATE INDEX IF NOT EXISTS idx_task_queue_program
  ON task_queue(platform, program_external_id);

COMMIT;
