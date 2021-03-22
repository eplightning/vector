use crate::config;
use tokio::stream::StreamExt;
use url::Url;
use vector_api_client::{connect_subscription_client, gql::TapSubscriptionExt, Client};

/// CLI command func for issuing 'tap' queries, and communicating with a local/remote
/// Vector API server via HTTP/WebSockets.
pub async fn cmd(opts: &super::Opts) -> exitcode::ExitCode {
    // Use the provided URL as the Vector GraphQL API server, or default to the local port
    // provided by the API config. This will work despite `api` and `api-client` being distinct
    // features; the config is available even if `api` is disabled.
    let mut url = opts.url.clone().unwrap_or_else(|| {
        let addr = config::api::default_address().unwrap();
        Url::parse(&*format!("http://{}/graphql", addr))
            .expect("Couldn't parse default API URL. Please report this.")
    });

    // Return early with instructions for enabling the API if the endpoint isn't reachable
    // via a healthcheck.
    if Client::new_with_healthcheck(url.clone()).await.is_none() {
        return exitcode::UNAVAILABLE;
    }

    // Change the HTTP schema to WebSockets.
    url.set_scheme(match url.scheme() {
        "https" => "wss",
        _ => "ws",
    })
    .expect("Couldn't build WebSocket URL. Please report.");

    let subscription_client = match connect_subscription_client(url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Couldn't connect to Vector API via WebSockets: {:?}", e);
            return exitcode::UNAVAILABLE;
        }
    };

    // Issue the 'tap' request, printing to stdout.
    let res = subscription_client.output_log_events_subscription(
        opts.components.clone(),
        opts.format,
        opts.limit as i64,
        opts.interval as i64,
    );

    tokio::pin! {
        let stream = res.stream();
    };

    while let Some(Some(res)) = stream.next().await {
        if let Some(d) = res.data {
            for formatted_string in d
                .output_log_events
                .iter()
                .filter_map(|ev| ev.as_log()?.string.as_ref())
            {
                println!("{}", formatted_string);
            }
        }
    }

    exitcode::OK
}
