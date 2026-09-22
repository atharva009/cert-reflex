package dev.atharva.certreflex.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;

/**
 * Scheduling plus ShedLock.
 *
 * <p>A second instance of this application would otherwise race the first to
 * rotate the same certificate. Only one instance ever runs in this demo, but
 * the lock is what makes that a property of the design rather than of the
 * deployment.
 *
 * <p>{@code defaultLockAtMostFor} is a backstop for a job that dies without
 * releasing its lock; the watcher sets its own, shorter value.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "PT1M")
public class SchedulingConfiguration {

    @Bean
    LockProvider lockProvider(DataSource dataSource) {
        return new JdbcTemplateLockProvider(JdbcTemplateLockProvider.Configuration.builder()
                .withJdbcTemplate(new JdbcTemplate(dataSource))
                // UTC from the database clock rather than this process's clock,
                // and it uses the INSERT form that avoids conflicts.
                .usingDbTime()
                .build());
    }
}
