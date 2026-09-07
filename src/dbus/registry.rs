//! Register and unregister collection, alias, and item objects; shared notifications.

use super::collection::{Collection, CollectionAdmin, CollectionRef};
use super::item::Item;
use super::paths;
use super::service::{Service, ServiceSignals};
use super::state::Shared;
use zbus::Connection;
use zbus::object_server::SignalEmitter;

pub async fn register_collection(conn: &Connection, state: &Shared, id: &str) -> zbus::Result<()> {
    let server = conn.object_server();
    server
        .at(
            paths::collection(id),
            Collection::new(state.clone(), CollectionRef::Id(id.to_string())),
        )
        .await?;
    // The private batch interface rides on the same object; see
    // `collection::CollectionAdmin`.
    server
        .at(
            paths::collection(id),
            CollectionAdmin::new(state.clone(), CollectionRef::Id(id.to_string())),
        )
        .await?;
    let item_ids = state
        .lock()
        .await
        .collections
        .get(id)
        .map(|v| v.item_ids())
        .unwrap_or_default();
    for iid in item_ids {
        server
            .at(
                paths::item(id, &iid),
                Item::new(state.clone(), id.to_string(), iid),
            )
            .await?;
    }
    Ok(())
}

pub async fn unregister_collection(conn: &Connection, id: &str, item_ids: &[String]) {
    let server = conn.object_server();
    for iid in item_ids {
        if let Err(e) = server.remove::<Item, _>(paths::item(id, iid)).await {
            tracing::debug!("removing item '{iid}' of '{id}': {e}");
        }
    }
    if let Err(e) = server
        .remove::<CollectionAdmin, _>(paths::collection(id))
        .await
    {
        tracing::debug!("removing admin interface of '{id}': {e}");
    }
    if let Err(e) = server.remove::<Collection, _>(paths::collection(id)).await {
        tracing::debug!("removing collection '{id}': {e}");
    }
}

/// Idempotent: an alias object resolves its target at call time, so it is
/// registered once and never removed.
pub async fn register_alias(conn: &Connection, state: &Shared, name: &str) -> zbus::Result<()> {
    if let Some(path) = paths::alias(name) {
        let server = conn.object_server();
        server
            .at(
                path.clone(),
                Collection::new(state.clone(), CollectionRef::Alias(name.to_string())),
            )
            .await?;
        server
            .at(
                path,
                CollectionAdmin::new(state.clone(), CollectionRef::Alias(name.to_string())),
            )
            .await?;
    }
    Ok(())
}

pub async fn register_item(
    conn: &Connection,
    state: &Shared,
    collection_id: &str,
    item_id: &str,
) -> zbus::Result<()> {
    conn.object_server()
        .at(
            paths::item(collection_id, item_id),
            Item::new(
                state.clone(),
                collection_id.to_string(),
                item_id.to_string(),
            ),
        )
        .await?;
    Ok(())
}

pub async fn register_all(conn: &Connection, state: &Shared) -> zbus::Result<()> {
    let (ids, aliases) = {
        let st = state.lock().await;
        (
            st.collections
                .keys()
                .chain(st.broken.keys())
                .cloned()
                .collect::<Vec<_>>(),
            st.aliases.keys().cloned().collect::<Vec<_>>(),
        )
    };
    for id in ids {
        register_collection(conn, state, &id).await?;
    }
    for name in aliases {
        register_alias(conn, state, &name).await?;
    }
    Ok(())
}

/// `Service.CollectionChanged` plus `PropertiesChanged` for `Collection.Locked`,
/// on both the collection's real path and every alias that currently targets
/// it (an alias is its own D-Bus object with its own cached `Locked`
/// property, so it needs its own `PropertiesChanged` — see `register_alias`).
///
/// Signature kept as `(conn, id)`, matching every existing caller: the
/// collection's own registered interface is used to reach `ServiceState`
/// (via `Collection::state`) instead of taking a redundant `&Shared`.
pub async fn notify_collection_changed(conn: &Connection, id: &str) {
    if let Ok(emitter) = SignalEmitter::new(conn, paths::SERVICE_PATH)
        && let Err(e) = emitter.collection_changed(paths::collection(id)).await
    {
        tracing::warn!("emitting CollectionChanged for '{id}': {e}");
    }
    let Ok(iface) = conn
        .object_server()
        .interface::<_, Collection>(paths::collection(id))
        .await
    else {
        return;
    };
    let aliases: Vec<String> = {
        let coll = iface.get().await;
        let st = coll.state().lock().await;
        st.aliases
            .iter()
            .filter(|(_, target)| target.as_str() == id)
            .map(|(name, _)| name.clone())
            .collect()
    };
    emit_locked_changed(conn, paths::collection(id)).await;
    for name in aliases {
        if let Some(path) = paths::alias(&name) {
            emit_locked_changed(conn, path).await;
        }
    }
}

async fn emit_locked_changed(conn: &Connection, path: zbus::zvariant::OwnedObjectPath) {
    if let Ok(iface) = conn.object_server().interface::<_, Collection>(path).await
        && let Err(e) = iface
            .get()
            .await
            .locked_changed(iface.signal_emitter())
            .await
    {
        tracing::warn!("emitting Locked PropertiesChanged: {e}");
    }
}

/// `PropertiesChanged` for `Service.Collections`, after a collection is created or deleted.
pub async fn notify_collections_changed(conn: &Connection) {
    if let Ok(iface) = conn
        .object_server()
        .interface::<_, Service>(paths::SERVICE_PATH)
        .await
    {
        let _ = iface
            .get()
            .await
            .collections_changed(iface.signal_emitter())
            .await;
    }
}
