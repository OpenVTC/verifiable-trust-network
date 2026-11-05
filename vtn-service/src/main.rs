use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use vtn_service::config::Config;
use vtn_service::setup;

#[derive(Parser)]
#[command(name = "vtn", about = "Verifiable Trust Network service", version)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, short, default_value = "vtn.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provision the network's identity from a VTA (two phases: `--setup-key-out`, then
    /// `--from`).
    Setup {
        /// Phase 1: mint the ephemeral setup key into this file and print the VTA grant.
        #[arg(long, conflicts_with = "from")]
        setup_key_out: Option<PathBuf>,
        /// Phase 1: the VTA context the grant names.
        #[arg(long, default_value = setup::DEFAULT_CONTEXT, requires = "setup_key_out")]
        context: String,
        /// Phase 2: provision from this setup file.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Create a development `did:key` identity (no VTA) and print its DID.
    Init,
    /// Print the network DID.
    Did,
    /// Run the service.
    Serve,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    // Before any secret store is opened. Only a warning: the OS credential store is one
    // backend of several, and a server using another one need not have it.
    #[cfg(feature = "keyring")]
    vta_sdk::keyring_init::warn_store_unavailable("vtn");

    match cli.command {
        Command::Setup {
            setup_key_out: Some(out),
            context,
            ..
        } => setup::run_phase1(&out, &context).await?,
        Command::Setup {
            from: Some(path), ..
        } => setup::run_from_file(&path).await?,
        Command::Setup { .. } => {
            anyhow::bail!("give --setup-key-out <path> (phase 1) or --from <setup.toml> (phase 2)")
        }
        Command::Init => println!("{}", vtn_service::init_dev(&Config::load(&cli.config)?)?),
        Command::Did => {
            let config = Config::load(&cli.config)?;
            println!("{}", vtn_service::identity::load(&config).await?.did());
        }
        Command::Serve => {
            let config = Config::load(&cli.config)?;
            let state = vtn_service::build_state(&config).await?;
            tracing::info!(
                did = state.network.did(),
                listen = %config.listen,
                admins = state.auth.admins().len(),
                provisioned = config.identity.is_some(),
                "VTN starting"
            );
            state
                .network
                .spawn_retry_worker(std::time::Duration::from_secs(15));
            // The trust-registry projection: reconciled now (which adds existing members),
            // after every entry change, and every `sync_interval_secs`.
            if let Some(registry) = &config.registry {
                let syncer = std::sync::Arc::new(vtn_service::registry::Syncer::new(
                    state.network.clone(),
                    std::sync::Arc::new(vtn_service::registry::NoWriteTransport),
                    registry.clone(),
                ));
                tracing::info!(
                    registry = %registry.did,
                    publish = registry.publish.as_str(),
                    writer = syncer.writer().describe(),
                    "trust registry projection on"
                );
                syncer.spawn();
            }
            // Accepted Trust Task ids are kept for their acceptance window, then dropped.
            let accepted = state.accepted.clone();
            let oob = state.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
                loop {
                    tick.tick().await;
                    if let Err(e) = accepted.prune(chrono::Utc::now()).await {
                        tracing::warn!(error = %e, "pruning accepted Trust Task ids failed");
                    }
                    if let Err(e) = vtn_service::tasks::oob::sweep(&oob).await {
                        tracing::warn!(error = %e, "sweeping browser sign-in requests failed");
                    }
                }
            });
            let listener = tokio::net::TcpListener::bind(&config.listen).await?;
            axum::serve(
                listener,
                vtn_service::routes::router(state)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
        }
    }
    Ok(())
}
