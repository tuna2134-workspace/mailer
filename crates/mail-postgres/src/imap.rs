use super::{MailboxRepository, PostgresRepository, SmtpRepository, map_sqlx};
use async_trait::async_trait;
use mail_domain::{MailboxId, TenantId};
use mail_storage::{
    ImapMailbox, ImapMessage, ImapRepository, MailboxMessageState, SmtpAuthAccount, StorageError,
    StoreFlags,
};
use sqlx::Row;
use std::time::{Duration, UNIX_EPOCH};
use uuid::Uuid;

#[async_trait]
impl ImapRepository for PostgresRepository {
    async fn imap_auth_account(
        &self,
        identity: &str,
    ) -> Result<Option<SmtpAuthAccount>, StorageError> {
        SmtpRepository::smtp_auth_account(self, identity).await
    }

    async fn record_imap_auth(&self, user_id: Uuid, success: bool) -> Result<(), StorageError> {
        SmtpRepository::record_smtp_auth(self, user_id, success).await
    }

    async fn imap_mailboxes(&self, user_id: Uuid) -> Result<Vec<ImapMailbox>, StorageError> {
        let rows = sqlx::query("SELECT m.id,m.name,m.uid_validity,m.uid_next,m.highest_modseq,m.message_count,m.unseen_count,s.mailbox_id IS NOT NULL AS subscribed FROM mailboxes m LEFT JOIN imap_subscriptions s ON s.user_id=m.user_id AND s.mailbox_id=m.id WHERE m.user_id=$1 ORDER BY m.name")
            .bind(user_id).fetch_all(self.pool()).await.map_err(map_sqlx)?;
        rows.iter().map(mailbox).collect()
    }

    async fn imap_create_mailbox(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<ImapMailbox, StorageError> {
        let row = sqlx::query("INSERT INTO mailboxes(id,tenant_id,user_id,name,uid_validity) SELECT $1,tenant_id,id,$2,nextval('mailbox_uidvalidity_seq') FROM users WHERE id=$3 AND status='active' RETURNING id,name,uid_validity,uid_next,highest_modseq,message_count,unseen_count,false AS subscribed")
            .bind(Uuid::new_v4()).bind(name).bind(user_id).fetch_optional(self.pool()).await.map_err(map_sqlx)?.ok_or(StorageError::NotFound)?;
        mailbox(&row)
    }

    async fn imap_rename_mailbox(
        &self,
        user_id: Uuid,
        from: &str,
        to: &str,
    ) -> Result<(), StorageError> {
        let changed = sqlx::query("UPDATE mailboxes SET name=$3,version=version+1 WHERE user_id=$1 AND name=$2 AND lower(name)<>'inbox'")
            .bind(user_id).bind(from).bind(to).execute(self.pool()).await.map_err(map_sqlx)?.rows_affected();
        (changed == 1).then_some(()).ok_or(StorageError::NotFound)
    }

    async fn imap_delete_mailbox(&self, user_id: Uuid, name: &str) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(map_sqlx)?;
        let id:Uuid=sqlx::query_scalar("SELECT id FROM mailboxes WHERE user_id=$1 AND name=$2 AND lower(name)<>'inbox' AND message_count=0 FOR UPDATE").bind(user_id).bind(name).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::Conflict)?;
        sqlx::query("DELETE FROM mailbox_messages WHERE mailbox_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        let changed = sqlx::query("DELETE FROM mailboxes WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?
            .rows_affected();
        tx.commit().await.map_err(map_sqlx)?;
        (changed == 1).then_some(()).ok_or(StorageError::Conflict)
    }

    async fn imap_subscribe(
        &self,
        user_id: Uuid,
        name: &str,
        subscribe: bool,
    ) -> Result<(), StorageError> {
        let result = if subscribe {
            sqlx::query("INSERT INTO imap_subscriptions(user_id,mailbox_id) SELECT $1,id FROM mailboxes WHERE user_id=$1 AND name=$2 ON CONFLICT DO NOTHING")
                .bind(user_id).bind(name).execute(self.pool()).await
        } else {
            sqlx::query("DELETE FROM imap_subscriptions WHERE user_id=$1 AND mailbox_id=(SELECT id FROM mailboxes WHERE user_id=$1 AND name=$2)")
                .bind(user_id).bind(name).execute(self.pool()).await
        };
        result.map(|_| ()).map_err(map_sqlx)
    }

    async fn imap_messages(
        &self,
        user_id: Uuid,
        mailbox_id: MailboxId,
    ) -> Result<Vec<ImapMessage>, StorageError> {
        let rows = sqlx::query("SELECT row_number() OVER(ORDER BY mm.uid)::bigint AS sequence,mm.uid,mm.modseq,mm.flags||mm.keywords AS flags,extract(epoch FROM mm.internal_date)::bigint AS internal_date,msg.raw_message FROM mailbox_messages mm JOIN mailboxes m ON m.id=mm.mailbox_id JOIN messages msg ON msg.id=mm.message_id WHERE m.user_id=$1 AND m.id=$2 AND mm.expunged_at IS NULL ORDER BY mm.uid")
            .bind(user_id).bind(mailbox_id.into_uuid()).fetch_all(self.pool()).await.map_err(map_sqlx)?;
        rows.iter().map(message).collect()
    }

    async fn imap_append(
        &self,
        user_id: Uuid,
        mailbox_name: &str,
        raw: &[u8],
    ) -> Result<(u32, u32), StorageError> {
        let mut tx = self.pool().begin().await.map_err(map_sqlx)?;
        let owner = sqlx::query("SELECT m.id,m.tenant_id,m.uid_validity FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND m.name=$2 AND u.status='active' FOR UPDATE OF m,u")
            .bind(user_id).bind(mailbox_name).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::NotFound)?;
        let mailbox_id: Uuid = owner.try_get("id").map_err(map_sqlx)?;
        let tenant_id: Uuid = owner.try_get("tenant_id").map_err(map_sqlx)?;
        let size = i64::try_from(raw.len()).map_err(|_| StorageError::QuotaExceeded)?;
        if sqlx::query("UPDATE users SET used_bytes=used_bytes+$2 WHERE id=$1 AND used_bytes<=quota_bytes-$2").bind(user_id).bind(size).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected()!=1
            || sqlx::query("UPDATE tenants SET used_bytes=used_bytes+$2 WHERE id=$1 AND used_bytes<=quota_bytes-$2").bind(tenant_id).bind(size).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected()!=1 { return Err(StorageError::QuotaExceeded); }
        let message_id = Uuid::new_v4();
        sqlx::query("INSERT INTO messages(id,tenant_id,raw_message,envelope_sender,received_at,message_size,content_hash,storage_state) VALUES($1,$2,$3,'',clock_timestamp(),$4,digest($3,'sha256'),'committed')")
            .bind(message_id).bind(tenant_id).bind(raw).bind(size).execute(&mut *tx).await.map_err(map_sqlx)?;
        let allocated=sqlx::query("UPDATE mailboxes SET uid_next=uid_next+1,highest_modseq=highest_modseq+1,message_count=message_count+1,unseen_count=unseen_count+1 WHERE id=$1 AND uid_next<4294967295 AND highest_modseq<9223372036854775807 RETURNING uid_next-1 AS uid")
            .bind(mailbox_id).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::CounterExhausted)?;
        let uid: i64 = allocated.try_get("uid").map_err(map_sqlx)?;
        sqlx::query("INSERT INTO mailbox_messages(mailbox_id,message_id,uid,modseq,internal_date,object_id) SELECT $1,$2,$3,highest_modseq,clock_timestamp(),$4 FROM mailboxes WHERE id=$1")
            .bind(mailbox_id).bind(message_id).bind(uid).bind(Uuid::new_v4()).execute(&mut *tx).await.map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok((
            u32::try_from(owner.try_get::<i64, _>("uid_validity").map_err(map_sqlx)?)
                .map_err(|_| StorageError::Conflict)?,
            u32::try_from(uid).map_err(|_| StorageError::Conflict)?,
        ))
    }

    async fn imap_copy(
        &self,
        user_id: Uuid,
        source: MailboxId,
        uids: &[u32],
        destination: &str,
        move_messages: bool,
    ) -> Result<Vec<u32>, StorageError> {
        let mut tx = self.pool().begin().await.map_err(map_sqlx)?;
        let destination_id: Uuid =
            sqlx::query_scalar("SELECT id FROM mailboxes WHERE user_id=$1 AND name=$2 FOR UPDATE")
                .bind(user_id)
                .bind(destination)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?
                .ok_or(StorageError::NotFound)?;
        if destination_id == source.into_uuid() {
            return Err(StorageError::Conflict);
        }
        let mut copied = Vec::with_capacity(uids.len());
        for uid in uids {
            let row=sqlx::query("SELECT mm.message_id,mm.flags,msg.message_size FROM mailbox_messages mm JOIN mailboxes m ON m.id=mm.mailbox_id JOIN messages msg ON msg.id=mm.message_id WHERE m.user_id=$1 AND m.id=$2 AND mm.uid=$3 AND mm.expunged_at IS NULL FOR UPDATE OF mm")
                .bind(user_id).bind(source.into_uuid()).bind(i64::from(*uid)).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::NotFound)?;
            let flags: Vec<String> = row.try_get("flags").map_err(map_sqlx)?;
            let unseen = i64::from(!flags.iter().any(|flag| flag == "\\Seen"));
            if !move_messages && sqlx::query("UPDATE users SET used_bytes=used_bytes+$2 WHERE id=$1 AND used_bytes<=quota_bytes-$2").bind(user_id).bind(row.try_get::<i64,_>("message_size").map_err(map_sqlx)?).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected()!=1 {
                return Err(StorageError::QuotaExceeded);
            }
            let allocation=sqlx::query("UPDATE mailboxes SET uid_next=uid_next+1,highest_modseq=highest_modseq+1,message_count=message_count+1,unseen_count=unseen_count+$2 WHERE id=$1 AND uid_next<4294967295 AND highest_modseq<9223372036854775807 RETURNING uid_next-1 AS uid,highest_modseq")
                .bind(destination_id).bind(unseen).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::CounterExhausted)?;
            let new_uid: i64 = allocation.try_get("uid").map_err(map_sqlx)?;
            sqlx::query("INSERT INTO mailbox_messages(mailbox_id,message_id,uid,modseq,flags,keywords,internal_date,saved_date,object_id) SELECT $1,message_id,$2,$3,flags,keywords,internal_date,clock_timestamp(),$4 FROM mailbox_messages WHERE mailbox_id=$5 AND uid=$6")
                .bind(destination_id).bind(new_uid).bind(allocation.try_get::<i64,_>("highest_modseq").map_err(map_sqlx)?).bind(Uuid::new_v4()).bind(source.into_uuid()).bind(i64::from(*uid)).execute(&mut *tx).await.map_err(map_sqlx)?;
            copied.push(u32::try_from(new_uid).map_err(|_| StorageError::Conflict)?);
            if move_messages {
                let modseq:i64=sqlx::query_scalar("UPDATE mailboxes SET highest_modseq=highest_modseq+1,message_count=message_count-1,unseen_count=unseen_count-$2 WHERE id=$1 AND highest_modseq<9223372036854775807 RETURNING highest_modseq").bind(source.into_uuid()).bind(unseen).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::CounterExhausted)?;
                sqlx::query("UPDATE mailbox_messages SET expunged_at=clock_timestamp(),modseq=$3 WHERE mailbox_id=$1 AND uid=$2").bind(source.into_uuid()).bind(i64::from(*uid)).bind(modseq).execute(&mut *tx).await.map_err(map_sqlx)?;
            }
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(copied)
    }

    async fn imap_store_flags(
        &self,
        user_id: Uuid,
        mailbox: MailboxId,
        uids: &[u32],
        update: &StoreFlags,
    ) -> Result<Vec<MailboxMessageState>, StorageError> {
        owns(self, user_id, mailbox).await?;
        let mut states = Vec::with_capacity(uids.len());
        for uid in uids {
            states.push(
                MailboxRepository::store_flags(
                    self,
                    tenant(self, user_id).await?,
                    mailbox,
                    *uid,
                    update,
                )
                .await?,
            );
        }
        Ok(states)
    }

    async fn imap_expunge(
        &self,
        user_id: Uuid,
        mailbox: MailboxId,
        uids: Option<&[u32]>,
    ) -> Result<Vec<u32>, StorageError> {
        let mut tx = self.pool().begin().await.map_err(map_sqlx)?;
        let rows=sqlx::query("SELECT mm.uid,mm.flags,msg.message_size FROM mailbox_messages mm JOIN mailboxes m ON m.id=mm.mailbox_id JOIN users u ON u.id=m.user_id JOIN messages msg ON msg.id=mm.message_id WHERE m.user_id=$1 AND m.id=$2 AND mm.expunged_at IS NULL AND mm.flags@>ARRAY['\\Deleted']::text[] ORDER BY mm.uid FOR UPDATE OF mm,m,u")
            .bind(user_id).bind(mailbox.into_uuid()).fetch_all(&mut *tx).await.map_err(map_sqlx)?;
        let mut removed = Vec::new();
        for row in rows {
            let uid = u32::try_from(row.try_get::<i64, _>("uid").map_err(map_sqlx)?)
                .map_err(|_| StorageError::Conflict)?;
            if uids.is_none_or(|set| set.contains(&uid)) {
                let flags: Vec<String> = row.try_get("flags").map_err(map_sqlx)?;
                let unseen = i64::from(!flags.iter().any(|flag| flag == "\\Seen"));
                let modseq:i64=sqlx::query_scalar("UPDATE mailboxes SET highest_modseq=highest_modseq+1,message_count=message_count-1,unseen_count=unseen_count-$3,version=version+1 WHERE id=$1 AND user_id=$2 AND highest_modseq<9223372036854775807 RETURNING highest_modseq").bind(mailbox.into_uuid()).bind(user_id).bind(unseen).fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StorageError::CounterExhausted)?;
                sqlx::query("UPDATE mailbox_messages SET expunged_at=clock_timestamp(),modseq=$3 WHERE mailbox_id=$1 AND uid=$2").bind(mailbox.into_uuid()).bind(i64::from(uid)).bind(modseq).execute(&mut *tx).await.map_err(map_sqlx)?;
                sqlx::query(
                    "UPDATE users SET used_bytes=used_bytes-$2 WHERE id=$1 AND used_bytes>=$2",
                )
                .bind(user_id)
                .bind(row.try_get::<i64, _>("message_size").map_err(map_sqlx)?)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
                removed.push(uid);
            }
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(removed)
    }
}

async fn tenant(repo: &PostgresRepository, user: Uuid) -> Result<TenantId, StorageError> {
    sqlx::query_scalar::<_, Uuid>("SELECT tenant_id FROM users WHERE id=$1")
        .bind(user)
        .fetch_optional(repo.pool())
        .await
        .map_err(map_sqlx)?
        .map(TenantId::new)
        .ok_or(StorageError::NotFound)
}

async fn owns(
    repo: &PostgresRepository,
    user: Uuid,
    mailbox: MailboxId,
) -> Result<(), StorageError> {
    sqlx::query_scalar::<_, i32>("SELECT 1 FROM mailboxes WHERE user_id=$1 AND id=$2")
        .bind(user)
        .bind(mailbox.into_uuid())
        .fetch_optional(repo.pool())
        .await
        .map_err(map_sqlx)?
        .map(|_| ())
        .ok_or(StorageError::NotFound)
}

fn mailbox(row: &sqlx::postgres::PgRow) -> Result<ImapMailbox, StorageError> {
    Ok(ImapMailbox {
        id: MailboxId::new(row.try_get("id").map_err(map_sqlx)?),
        name: row.try_get("name").map_err(map_sqlx)?,
        uid_validity: convert(row, "uid_validity")?,
        uid_next: convert(row, "uid_next")?,
        highest_modseq: u64::try_from(row.try_get::<i64, _>("highest_modseq").map_err(map_sqlx)?)
            .map_err(|_| StorageError::Conflict)?,
        message_count: convert64(row, "message_count")?,
        unseen_count: convert64(row, "unseen_count")?,
        subscribed: row.try_get("subscribed").map_err(map_sqlx)?,
    })
}
fn convert(row: &sqlx::postgres::PgRow, name: &str) -> Result<u32, StorageError> {
    u32::try_from(row.try_get::<i64, _>(name).map_err(map_sqlx)?)
        .map_err(|_| StorageError::Conflict)
}
fn convert64(row: &sqlx::postgres::PgRow, name: &str) -> Result<u64, StorageError> {
    u64::try_from(row.try_get::<i64, _>(name).map_err(map_sqlx)?)
        .map_err(|_| StorageError::Conflict)
}
fn message(row: &sqlx::postgres::PgRow) -> Result<ImapMessage, StorageError> {
    let seconds = u64::try_from(row.try_get::<i64, _>("internal_date").map_err(map_sqlx)?)
        .map_err(|_| StorageError::Conflict)?;
    Ok(ImapMessage {
        sequence: convert(row, "sequence")?,
        uid: convert(row, "uid")?,
        modseq: convert64(row, "modseq")?,
        flags: row.try_get("flags").map_err(map_sqlx)?,
        internal_date: UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or(StorageError::Conflict)?,
        raw: row.try_get("raw_message").map_err(map_sqlx)?,
    })
}
