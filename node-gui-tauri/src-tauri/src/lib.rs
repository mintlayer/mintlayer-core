// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
use std::sync::{Arc, Mutex};
use tauri::command;
use tokio::sync::mpsc::unbounded_channel;
use chainstate::ChianInfo;



#[tauri::command]


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
