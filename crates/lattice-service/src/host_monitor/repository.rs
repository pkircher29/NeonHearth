use super::*;
use chrono::{DateTime, Duration};
use serde_json::{Value, json};
use sqlx::Row;
impl HostMonitor {
    pub async fn settings(&self) -> Result<HostSettings, sqlx::Error> {
        let row=sqlx::query("SELECT record_history,snooze_until,retention_days,monthly_budget_bytes FROM host_settings WHERE id=1").fetch_one(&self.pool).await?;
        Ok(HostSettings {
            record_history: row.try_get("record_history")?,
            snooze_until: row.try_get("snooze_until")?,
            retention_days: row.try_get::<i64, _>("retention_days")? as u32,
            monthly_budget_bytes: row
                .try_get::<Option<i64>, _>("monthly_budget_bytes")?
                .map(|n| n as u64),
        })
    }
    pub async fn update_settings(&self, value: &HostSettings) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE host_settings SET record_history=?,snooze_until=?,retention_days=?,monthly_budget_bytes=? WHERE id=1")
            .bind(value.record_history).bind(&value.snooze_until).bind(value.retention_days).bind(value.monthly_budget_bytes.map(|v|v as i64)).execute(&self.pool).await?;
        Ok(())
    }
    pub(super) async fn persist(
        &self,
        snapshot: &HostSnapshot,
        previous: Option<&HostSnapshot>,
        samples: &[Sample],
    ) -> Result<(), sqlx::Error> {
        // Serialize the privacy check with settings writes. Once disabling
        // recording returns, an earlier collector read cannot write a frame.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row=sqlx::query("SELECT record_history,snooze_until,retention_days,monthly_budget_bytes FROM host_settings WHERE id=1").fetch_one(&mut *tx).await?;
        let settings = HostSettings {
            record_history: row.try_get("record_history")?,
            snooze_until: row.try_get("snooze_until")?,
            retention_days: row.try_get::<i64, _>("retention_days")? as u32,
            monthly_budget_bytes: row
                .try_get::<Option<i64>, _>("monthly_budget_bytes")?
                .map(|n| n as u64),
        };
        if !settings.record_history {
            return Ok(());
        }
        let now = Utc::now();
        let bucket = DateTime::from_timestamp(now.timestamp().div_euclid(60) * 60, 0)
            .unwrap_or(now)
            .to_rfc3339();
        let apps: BTreeMap<_, _> = snapshot
            .applications
            .iter()
            .map(|a| (&a.app_id, a))
            .collect();
        for app in apps.values() {
            let inserted=sqlx::query("INSERT INTO host_apps(app_id,name,executable,first_seen_at,last_seen_at) VALUES(?,?,?,?,?) ON CONFLICT(app_id) DO NOTHING")
                .bind(&app.app_id).bind(&app.name).bind(&app.executable).bind(&snapshot.observed_at).bind(&snapshot.observed_at).execute(&mut *tx).await?.rows_affected();
            sqlx::query("UPDATE host_apps SET last_seen_at=? WHERE app_id=?")
                .bind(&snapshot.observed_at)
                .bind(&app.app_id)
                .execute(&mut *tx)
                .await?;
            if inserted == 1 && previous.is_some() && app.executable.is_some() {
                sqlx::query("INSERT INTO host_alerts(observed_at,kind,app_id,detail) VALUES(?,'new_application',?,?)").bind(&snapshot.observed_at).bind(&app.app_id).bind(format!("{} first observed using a network socket.",app.name)).execute(&mut *tx).await?;
            }
        }
        let previous_connections: std::collections::BTreeSet<_> = previous
            .into_iter()
            .flat_map(|s| s.connections.iter().map(|c| c.connection_id.as_str()))
            .collect();
        for connection in &snapshot.connections {
            let inserted=sqlx::query("INSERT INTO host_connections(connection_id,app_id,protocol,local_address,local_port,remote_address,remote_port,state,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(connection_id) DO UPDATE SET state=excluded.state,last_seen_at=excluded.last_seen_at")
                .bind(&connection.connection_id).bind(&connection.app_id).bind(&connection.protocol).bind(&connection.local_address).bind(connection.local_port as i64).bind(&connection.remote_address).bind(connection.remote_port.map(i64::from)).bind(&connection.state).bind(&snapshot.observed_at).bind(&snapshot.observed_at).execute(&mut *tx).await?.rows_affected();
            let is_new = previous.is_some()
                && !previous_connections.contains(connection.connection_id.as_str());
            if inserted > 0
                && is_new
                && connection.protocol == "tcp"
                && connection.state == "established"
                && (connection.local_port == 3389 || connection.remote_port == Some(3389))
            {
                sqlx::query("INSERT INTO host_alerts(observed_at,kind,app_id,detail) VALUES(?,'rdp_port_connection',?,?)")
                    .bind(&snapshot.observed_at).bind(&connection.app_id).bind(format!("TCP connection on the standard Remote Desktop port with {}. Port observation alone does not verify an RDP session.",connection.remote_address.as_deref().unwrap_or("unknown peer"))).execute(&mut *tx).await?;
            }
        }
        for sample in samples {
            let sent = sample.sent_bytes.min(i64::MAX as u64) as i64;
            let received = sample.received_bytes.min(i64::MAX as u64) as i64;
            sqlx::query("INSERT INTO host_samples(observed_at,scope,subject,interval_ms,sent_bytes,received_bytes,coverage) VALUES(?,?,?,?,?,?,?) ON CONFLICT(observed_at,scope,subject) DO UPDATE SET interval_ms=interval_ms+excluded.interval_ms,sent_bytes=sent_bytes+excluded.sent_bytes,received_bytes=received_bytes+excluded.received_bytes")
                .bind(&bucket).bind(sample.scope).bind(&sample.subject).bind(sample.interval_ms as i64).bind(sent).bind(received).bind(sample.coverage).execute(&mut *tx).await?;
            if sample.scope == "app" {
                sqlx::query("UPDATE host_apps SET sent_bytes=sent_bytes+?,received_bytes=received_bytes+? WHERE app_id=?").bind(sent).bind(received).bind(&sample.subject).execute(&mut *tx).await?;
            }
        }
        // Minutely aggregation keeps long history affordable. All tables also
        // have hard caps; age cleanup and capacity cleanup use bound values.
        let cutoff = (now - Duration::days(i64::from(settings.retention_days))).to_rfc3339();
        let maintenance_due = previous.is_none_or(|p| {
            DateTime::parse_from_rfc3339(&p.observed_at).map_or(true, |at| {
                at.timestamp().div_euclid(60) != now.timestamp().div_euclid(60)
            })
        });
        if maintenance_due {
            if let Some(budget) = settings.monthly_budget_bytes {
                let month = now.format("%Y-%m-01T00:00:00+00:00").to_string();
                let total:i64=sqlx::query_scalar("SELECT COALESCE(SUM(sent_bytes+received_bytes),0) FROM host_samples WHERE scope='host' AND observed_at>=?").bind(&month).fetch_one(&mut *tx).await?;
                if total as u64 >= budget {
                    sqlx::query("INSERT INTO host_alerts(observed_at,kind,detail) SELECT ?,'usage_target',? WHERE NOT EXISTS(SELECT 1 FROM host_alerts WHERE kind='usage_target' AND observed_at>=?)")
                    .bind(&snapshot.observed_at).bind("This computer reached the configured monthly traffic target. Includes local-network traffic; this is not an ISP bill measurement.").bind(&month).execute(&mut *tx).await?;
                }
            }
            for table in ["host_samples", "host_connections", "host_alerts"] {
                let column = if table == "host_connections" {
                    "last_seen_at"
                } else {
                    "observed_at"
                };
                sqlx::query(&format!("DELETE FROM {table} WHERE {column} < ?"))
                    .bind(&cutoff)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("DELETE FROM host_samples WHERE id IN (SELECT id FROM host_samples ORDER BY observed_at DESC,id DESC LIMIT -1 OFFSET 500000)").execute(&mut *tx).await?;
            sqlx::query("DELETE FROM host_connections WHERE connection_id IN (SELECT connection_id FROM host_connections ORDER BY last_seen_at DESC LIMIT -1 OFFSET 20000)").execute(&mut *tx).await?;
            sqlx::query("DELETE FROM host_alerts WHERE id IN (SELECT id FROM host_alerts ORDER BY id DESC LIMIT -1 OFFSET 2000)").execute(&mut *tx).await?;
            sqlx::query("DELETE FROM host_apps WHERE last_seen_at < ? AND app_id NOT IN (SELECT app_id FROM host_connections) AND app_id NOT IN (SELECT app_id FROM host_firewall_rules)").bind(&cutoff).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn history(&self, minutes: u32, app: Option<&str>) -> Result<Value, sqlx::Error> {
        let now = Utc::now();
        let since = (now - Duration::minutes(i64::from(minutes))).to_rfc3339();
        let bucket = if minutes <= 360 {
            60
        } else if minutes <= 2880 {
            300
        } else {
            3600
        };
        let scope = if app.is_some() { "app" } else { "host" };
        let subject = app.unwrap_or("physical_interfaces");
        let rows=sqlx::query("SELECT (CAST(strftime('%s',observed_at) AS INTEGER)/?)*? AS at,SUM(sent_bytes) AS sent,SUM(received_bytes) AS received,SUM(interval_ms) AS measured_ms FROM host_samples WHERE observed_at>=? AND scope=? AND subject=? GROUP BY at ORDER BY at LIMIT 1500")
            .bind(bucket).bind(bucket).bind(&since).bind(scope).bind(subject).fetch_all(&self.pool).await?;
        let points:Vec<Value>=rows.iter().map(|row|json!({"at":row.get::<i64,_>("at"),"sent_bytes":row.get::<i64,_>("sent"),"received_bytes":row.get::<i64,_>("received"),"measured_ms":row.get::<i64,_>("measured_ms")})).collect();
        let rows=sqlx::query("SELECT a.app_id,a.name,a.executable,a.first_seen_at,a.last_seen_at,COALESCE(SUM(s.sent_bytes),0) AS sent,COALESCE(SUM(s.received_bytes),0) AS received,COUNT(s.id) AS samples FROM host_apps a LEFT JOIN host_samples s ON s.subject=a.app_id AND s.scope='app' AND s.observed_at>=? WHERE a.last_seen_at>=? GROUP BY a.app_id ORDER BY sent+received DESC,a.name LIMIT 2048")
            .bind(&since).bind(&since).fetch_all(&self.pool).await?;
        let applications:Vec<Value>=rows.iter().map(|r|json!({"app_id":r.get::<String,_>("app_id"),"name":r.get::<String,_>("name"),"executable":r.get::<Option<String>,_>("executable"),"first_seen_at":r.get::<String,_>("first_seen_at"),"last_seen_at":r.get::<String,_>("last_seen_at"),"sent_bytes":r.get::<i64,_>("sent"),"received_bytes":r.get::<i64,_>("received"),"samples":r.get::<i64,_>("samples")})).collect();
        let rows=sqlx::query("SELECT c.*,a.name FROM host_connections c JOIN host_apps a USING(app_id) WHERE c.last_seen_at>=? AND (? IS NULL OR c.app_id=?) ORDER BY c.last_seen_at DESC LIMIT 2048")
            .bind(&since).bind(app).bind(app).fetch_all(&self.pool).await?;
        let connections:Vec<Value>=rows.iter().map(|r|json!({"connection_id":r.get::<String,_>("connection_id"),"app_id":r.get::<String,_>("app_id"),"name":r.get::<String,_>("name"),"protocol":r.get::<String,_>("protocol"),"local_address":r.get::<String,_>("local_address"),"local_port":r.get::<i64,_>("local_port"),"remote_address":r.get::<Option<String>,_>("remote_address"),"remote_port":r.get::<Option<i64>,_>("remote_port"),"state":r.get::<String,_>("state"),"first_seen_at":r.get::<String,_>("first_seen_at"),"last_seen_at":r.get::<String,_>("last_seen_at")})).collect();
        let rows = sqlx::query("SELECT * FROM host_alerts ORDER BY id DESC LIMIT 2000")
            .fetch_all(&self.pool)
            .await?;
        let alerts:Vec<Value>=rows.iter().map(|r|json!({"id":r.get::<i64,_>("id"),"at":r.get::<String,_>("observed_at"),"kind":r.get::<String,_>("kind"),"app_id":r.get::<Option<String>,_>("app_id"),"detail":r.get::<String,_>("detail"),"acknowledged":r.get::<bool,_>("acknowledged")})).collect();
        let settings = self.settings().await?;
        let month = now.format("%Y-%m-01T00:00:00+00:00").to_string();
        let monthly:(i64,i64)=sqlx::query_as("SELECT COALESCE(SUM(sent_bytes),0),COALESCE(SUM(received_bytes),0) FROM host_samples WHERE scope='host' AND observed_at>=?").bind(&month).fetch_one(&self.pool).await?;
        Ok(
            json!({"since":since,"until":now.to_rfc3339(),"bucket_seconds":bucket,"scope":scope,"points":points,"applications":applications,"connections":connections,"alerts":alerts,"settings":settings,"month_usage":{"since":month,"sent_bytes":monthly.0,"received_bytes":monthly.1},"coverage":if app.is_some(){"sampled_tcp"}else{"physical_interfaces"}}),
        )
    }
    pub async fn acknowledge(&self, id: i64) -> Result<bool, sqlx::Error> {
        Ok(
            sqlx::query("UPDATE host_alerts SET acknowledged=1 WHERE id=?")
                .bind(id)
                .execute(&self.pool)
                .await?
                .rows_affected()
                == 1,
        )
    }
}
