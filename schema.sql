-- SQLite schema for the phishing detector

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL,
    verdict     TEXT    NOT NULL CHECK (verdict IN ('phishing', 'suspicious', 'safe')),
    probability REAL    NOT NULL,             -- model's phishing probability (0..1)
    reasons     TEXT,                         -- newline-separated explanation
    scanned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans (verdict);
CREATE INDEX IF NOT EXISTS idx_scans_time    ON scans (scanned_at);

-- Example queries used by the app:
--   SELECT verdict, COUNT(*) FROM scans GROUP BY verdict;
--   SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 50;
