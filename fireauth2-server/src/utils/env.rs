use crate::Result;

use std::net::{IpAddr, SocketAddr};

const LOCAL_HOST: &str = "127.0.0.1";
const DOCKER_HOST: &str = "0.0.0.0";

pub fn init() -> Result<()> {
    if !is_docker_running() {
        dotenvy::dotenv()?;
    }
    Ok(())
}

/// Check if an executable is running in a Docker container
/// based on an environment variable.
pub fn is_docker_running() -> bool {
    std::env::var("DOCKER_RUNNING")
        .ok()
        .is_some_and(|val| val.parse::<bool>().unwrap_or(false))
}

pub fn get_socket_addrs() -> Result<SocketAddr> {
    let port = get_port()?;
    let host = get_host()?;
    let addr = SocketAddr::new(host, port);
    Ok(addr)
}

/// Return the hostname to bind an application to based on the the
/// current environment type.
///
/// In general, use 127.0.0.1:<port> when testing locally and 0.0.0.0:<port> when
/// deploying to a remote host(with or without a reverse proxy or load balancer)
/// so that the server is accessible.
///
/// When an application is running from within a Docker container
/// it is equivalent to running the app on a remote host.
pub fn get_host() -> Result<IpAddr> {
    let host = if is_docker_running() {
        DOCKER_HOST
    } else {
        LOCAL_HOST
    };
    let ip_addr = host.parse::<IpAddr>()?;
    Ok(ip_addr)
}

/// Get the `PORT` environment variable.
pub fn get_port() -> Result<u16> {
    let port = std::env::var("PORT")
        .unwrap_or("8080".into())
        .parse::<u16>()?;
    Ok(port)
}
