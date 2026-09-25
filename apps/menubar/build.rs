//! Tauri's own build step: it reads `tauri.conf.json`, embeds the frontend and
//! the capabilities, and writes the context `tauri::generate_context!` reads.

fn main() {
    tauri_build::build()
}
