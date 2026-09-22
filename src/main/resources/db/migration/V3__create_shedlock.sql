-- Column types follow the ShedLock README's Postgres example, which specifies
-- TIMESTAMP rather than TIMESTAMPTZ. The provider is configured with
-- usingDbTime(), so both columns hold UTC from the database clock.
CREATE TABLE shedlock (
    name VARCHAR(64) NOT NULL,
    lock_until TIMESTAMP NOT NULL,
    locked_at TIMESTAMP NOT NULL,
    locked_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);
