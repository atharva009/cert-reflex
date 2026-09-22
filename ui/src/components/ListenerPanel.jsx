const SERIAL_PREFIX_LENGTH = 8;

const STATUS_COLOUR = {
  ACTIVE: 'var(--active)',
  EXPIRING: 'var(--expiring)',
  CORRUPTED: 'var(--corrupted)',
  FAILED: 'var(--corrupted)',
  ROTATING: 'var(--rotating)',
};

const STATUS_LABEL = {
  ACTIVE: 'Active',
  EXPIRING: 'Expiring',
  CORRUPTED: 'Corrupted',
  FAILED: 'Failed',
  ROTATING: 'Rotating',
};

/**
 * One listener: name, countdown, serial, status, two text actions.
 *
 * The serial is truncated from the padded 32-digit uppercase form the API
 * returns, so the prefix shown here matches `openssl x509 -noout -serial`
 * character for character.
 */
export default function ListenerPanel({ cert, secondsRemaining, justRotated, stale, onInject }) {
  // "Just rotated" is the honest label: the API reported ACTIVE, and the poll
  // before it reported EXPIRING or CORRUPTED. If the API ever hands us a live
  // ROTATING, that gets the same colour and its own word.
  const rotating = cert.status === 'ROTATING';
  const showRotating = rotating || (justRotated && cert.status === 'ACTIVE');
  const colour = showRotating ? 'var(--rotating)' : (STATUS_COLOUR[cert.status] ?? 'var(--muted)');
  const label = showRotating
    ? (rotating ? 'Rotating' : 'Just rotated')
    : (STATUS_LABEL[cert.status] ?? cert.status);

  const terminal = cert.status === 'FAILED';

  return (
    <article
      className="panel"
      style={{ '--status': colour }}
      data-service={cert.serviceName}
      data-status={cert.status}
      data-display={showRotating ? 'JUST_ROTATED' : cert.status}
    >
      <h2 className="service">{cert.serviceName}</h2>
      <span className="endpoint">{cert.port === null ? 'Port not configured' : `Port ${cert.port}`}</span>

      {/* Negative is real state, not an error to hide: expired and awaiting
          remediation, or a row stranded by a failure. */}
      <div className={`countdown${secondsRemaining < 0 || terminal ? ' past-due' : ''}`} data-testid="countdown">
        {secondsRemaining}
        <span className="unit">s</span>
      </div>

      <span className="readout" data-testid="serial" title={cert.serial}>
        {cert.serial.slice(0, SERIAL_PREFIX_LENGTH)}…
      </span>

      <span className="status" data-testid="status">{label}</span>
      {terminal && (
        <span className="terminal-note">
          Not retried automatically. Rotate manually to recover.
        </span>
      )}

      <div className="actions">
        <button type="button" disabled={stale} onClick={() => onInject(cert.serviceName, 'EXPIRE')}>
          expire
        </button>
        <button type="button" disabled={stale} onClick={() => onInject(cert.serviceName, 'CORRUPT')}>
          corrupt
        </button>
      </div>
    </article>
  );
}
