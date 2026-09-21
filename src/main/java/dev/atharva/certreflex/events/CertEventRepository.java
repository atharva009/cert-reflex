package dev.atharva.certreflex.events;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class CertEventRepository {

    private final JdbcClient jdbcClient;

    public CertEventRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public void insert(String serviceName, CertEventType eventType, String message) {
        jdbcClient.sql("""
                INSERT INTO cert_events (service_name, event_type, message)
                VALUES (:serviceName, :eventType, :message)
                """)
                .param("serviceName", serviceName)
                .param("eventType", eventType.name())
                .param("message", message)
                .update();
    }

    /** Newest last, which is the order the dashboard's scrolling log wants. */
    public List<CertEvent> findRecent(int limit) {
        return jdbcClient.sql("""
                SELECT id, service_name, event_type, message, created_at
                FROM (
                    SELECT id, service_name, event_type, message, created_at
                    FROM cert_events
                    ORDER BY id DESC
                    LIMIT :limit
                ) recent
                ORDER BY id ASC
                """)
                .param("limit", limit)
                .query(CertEventRepository::mapRow)
                .list();
    }

    private static CertEvent mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new CertEvent(
                rs.getLong("id"),
                rs.getString("service_name"),
                CertEventType.valueOf(rs.getString("event_type")),
                rs.getString("message"),
                rs.getObject("created_at", OffsetDateTime.class).toInstant());
    }
}
