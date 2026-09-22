package dev.atharva.certreflex.inventory;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Data access for the cert inventory.
 *
 * <p>Writes follow locked decision 4: one row per service for the lifetime of
 * the database. {@link #insert} is for a service that has never been seen;
 * rotation goes through {@link #updateAfterRotation}, never through an insert.
 * The partial unique index on {@code status = 'ACTIVE'} rejects a second
 * active row if that rule is ever broken.
 *
 * <p>Timestamps are truncated to whole seconds on the way in, because X.509
 * validity fields have no sub-second component and TIMESTAMPTZ does.
 */
@Repository
public class CertRepository {

    private static final String COLUMNS = """
            id, service_name, common_name, serial_number, not_before, not_after,
            status, cert_pem, cert_path, key_path, created_at, updated_at
            """;

    private final JdbcClient jdbcClient;

    public CertRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public List<CertRecord> findAll() {
        return jdbcClient.sql("SELECT " + COLUMNS + " FROM certs ORDER BY service_name")
                .query(CertRepository::mapRow)
                .list();
    }

    public Optional<CertRecord> findByServiceName(String serviceName) {
        return jdbcClient.sql("SELECT " + COLUMNS + " FROM certs WHERE service_name = :serviceName")
                .param("serviceName", serviceName)
                .query(CertRepository::mapRow)
                .optional();
    }

    /** Rows whose remaining lifetime has fallen under the rotate threshold. */
    public List<CertRecord> findDueForRotation(Duration threshold) {
        return jdbcClient.sql("SELECT " + COLUMNS + """
                 FROM certs
                 WHERE status = 'ACTIVE'
                   AND not_after - now() < make_interval(secs => :seconds)
                 ORDER BY not_after
                """)
                .param("seconds", (double) threshold.toMillis() / 1000d)
                .query(CertRepository::mapRow)
                .list();
    }

    /**
     * Rows a previous watcher pass marked and has not yet remediated.
     *
     * <p>Deliberately a separate query from {@link #findDueForRotation}, which
     * filters on ACTIVE. Widening that one to cover these statuses would also
     * catch a row still in ROTATING from a slow rotation and rotate it twice.
     */
    public List<CertRecord> findAwaitingRemediation() {
        return jdbcClient.sql("SELECT " + COLUMNS + """
                 FROM certs
                 WHERE status IN ('EXPIRING', 'CORRUPTED')
                 ORDER BY service_name
                """)
                .query(CertRepository::mapRow)
                .list();
    }

    /** First row for a service. Never call this on a rotation. */
    public void insert(String serviceName, String commonName, BigInteger serialNumber,
            Instant notBefore, Instant notAfter, CertStatus status,
            String certPem, String certPath, String keyPath) {
        jdbcClient.sql("""
                INSERT INTO certs (service_name, common_name, serial_number, not_before, not_after,
                                   status, cert_pem, cert_path, key_path)
                VALUES (:serviceName, :commonName, :serialNumber, :notBefore, :notAfter,
                        :status, :certPem, :certPath, :keyPath)
                """)
                .param("serviceName", serviceName)
                .param("commonName", commonName)
                .param("serialNumber", new BigDecimal(serialNumber))
                .param("notBefore", timestamp(notBefore))
                .param("notAfter", timestamp(notAfter))
                .param("status", status.name())
                .param("certPem", certPem)
                .param("certPath", certPath)
                .param("keyPath", keyPath)
                .update();
    }

    public int updateStatus(String serviceName, CertStatus status) {
        return jdbcClient.sql("""
                UPDATE certs SET status = :status, updated_at = now()
                WHERE service_name = :serviceName
                """)
                .param("status", status.name())
                .param("serviceName", serviceName)
                .update();
    }

    public int updateAfterRotation(String serviceName, BigInteger serialNumber,
            Instant notBefore, Instant notAfter, String certPem) {
        return jdbcClient.sql("""
                UPDATE certs
                SET serial_number = :serialNumber,
                    not_before = :notBefore,
                    not_after = :notAfter,
                    cert_pem = :certPem,
                    status = 'ACTIVE',
                    updated_at = now()
                WHERE service_name = :serviceName
                """)
                .param("serialNumber", new BigDecimal(serialNumber))
                .param("notBefore", timestamp(notBefore))
                .param("notAfter", timestamp(notAfter))
                .param("certPem", certPem)
                .param("serviceName", serviceName)
                .update();
    }

    private static OffsetDateTime timestamp(Instant instant) {
        return OffsetDateTime.ofInstant(instant.truncatedTo(ChronoUnit.SECONDS), ZoneOffset.UTC);
    }

    private static CertRecord mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new CertRecord(
                rs.getObject("id", java.util.UUID.class),
                rs.getString("service_name"),
                rs.getString("common_name"),
                rs.getBigDecimal("serial_number").toBigIntegerExact(),
                instant(rs, "not_before"),
                instant(rs, "not_after"),
                CertStatus.valueOf(rs.getString("status")),
                rs.getString("cert_pem"),
                rs.getString("cert_path"),
                rs.getString("key_path"),
                instant(rs, "created_at"),
                instant(rs, "updated_at"));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        return rs.getObject(column, OffsetDateTime.class).toInstant();
    }
}
