use config_common::defaults::setup_env;
use std::sync::Arc;
use tauri::App;
use tokio::sync::RwLock;

pub mod config;
mod error;
mod logging;
mod models;
pub mod operations;
mod state;
mod tasks;

#[cfg(desktop)]
mod menu;
#[cfg(desktop)]
mod window;

pub use state::State;

#[cfg(mobile)]
mod mobile;
#[cfg(mobile)]
pub use mobile::*;

pub type SetupHook = Box<dyn FnOnce(&mut App) -> Result<(), Box<dyn std::error::Error>> + Send>;

#[derive(Default)]
pub struct AppBuilder {
    setup: Option<SetupHook>,
}

impl AppBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn setup<F>(mut self, setup: F) -> Self
    where
        F: FnOnce(&mut App) -> Result<(), Box<dyn std::error::Error>> + Send + 'static,
    {
        self.setup.replace(Box::new(setup));
        self
    }

    pub fn run(self) {
        setup_env(None);

        println!("Starting up...");
        let setup = self.setup;
        tauri::Builder::default()
            .manage(Arc::new(RwLock::new(State::default())))
            .invoke_handler(tauri::generate_handler![
                crate::config::get_config_file_location,
                crate::config::get_config_id,
                crate::operations::connection::status::get_connection_status,
                crate::operations::connection::connect::get_gateway,
                crate::operations::connection::connect::get_service_provider,
                crate::operations::connection::connect::set_gateway,
                crate::operations::connection::connect::set_service_provider,
                crate::operations::connection::connect::start_connecting,
                crate::operations::connection::disconnect::start_disconnecting,
                crate::operations::directory::get_services,
                crate::operations::export::export_keys,
                // crate::operations::window::hide_window,
                // crate::operations::growth::test_and_earn::growth_tne_get_client_id,
                // crate::operations::growth::test_and_earn::growth_tne_take_part,
                // crate::operations::growth::test_and_earn::growth_tne_get_draws,
                // crate::operations::growth::test_and_earn::growth_tne_ping,
                // crate::operations::growth::test_and_earn::growth_tne_submit_wallet_address,
                // crate::operations::growth::test_and_earn::growth_tne_enter_draw,
                // crate::operations::growth::test_and_earn::growth_tne_toggle_window,
                // crate::operations::help::log::help_log_toggle_window,
            ])
            .setup(move |app| {
                if let Some(setup) = setup {
                    (setup)(app)?;
                }
                Ok(())
            })
            .run(tauri::generate_context!())
            .expect("error while running tauri application");
    }
}
