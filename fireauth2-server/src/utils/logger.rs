use crate::Result;

pub fn init() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::new().default_filter_or("fireauth2=debug"),
    )
    .init();
    Ok(())
}
