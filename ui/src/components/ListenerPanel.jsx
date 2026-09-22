const SERIAL_PREFIX_LENGTH = 8;

/**
 * One listener. The serial is truncated from the padded 32-digit uppercase
 * form the API returns, so the prefix shown here matches
 * `openssl x509 -noout -serial` character for character.
 */
export default function ListenerPanel({ cert, secondsRemaining, stale, onInject }) {
  return (
    <article data-service={cert.serviceName} data-status={cert.status}>
      <h2>{cert.serviceName}</h2>
      <dl>
        <dt>status</dt>
        <dd data-testid="status">{cert.status}</dd>

        <dt>port</dt>
        {/* null for a row whose service is no longer configured */}
        <dd>{cert.port ?? '—'}</dd>

        <dt>expires in</dt>
        {/* Negative is real state: expired and awaiting remediation. Not clamped. */}
        <dd data-testid="countdown">{secondsRemaining}s</dd>

        <dt>serial</dt>
        <dd data-testid="serial" title={cert.serial}>
          {cert.serial.slice(0, SERIAL_PREFIX_LENGTH)}…
        </dd>
      </dl>

      <div>
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
