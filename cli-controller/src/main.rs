#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod crypto;
mod github;
mod db;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("C2 Controller"),
        ..Default::default()
    };

    eframe::run_native(
        "C2 Controller",
        options,
        Box::new(|cc| {
            // 启用中文字体支持
            cc.egui_ctx.style_mut(|style| {
                style.text_styles.insert(
                    egui::TextStyle::Body,
                    egui::FontId::proportional(14.0),
                );
            });

            let app = app::App::new(cc);
            Ok(Box::new(app))
        }),
    )
}
