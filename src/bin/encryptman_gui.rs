use eframe::{egui, App, Frame};
use std::process::Command;

#[derive(Default)]
struct EncryptmanApp {
    vault_path: String,
    source_path: String,
    dest_path: String,
    password: String,
    output: String,
}

impl App for EncryptmanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Encryptman GUI");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Vault Path:");
                ui.text_edit_singleline(&mut self.vault_path);
            });
            ui.horizontal(|ui| {
                ui.label("Source Path:");
                ui.text_edit_singleline(&mut self.source_path);
            });
            ui.horizontal(|ui| {
                ui.label("Destination Path:");
                ui.text_edit_singleline(&mut self.dest_path);
            });
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
            });

            ui.horizontal(|ui| {
                if ui.button("Create Vault").clicked() {
                    self.run_command(&["create", "--path", &self.vault_path, "--password", &self.password]);
                }
                if ui.button("Encrypt").clicked() {
                    if !self.source_path.is_empty() {
                        self.run_command(&["encrypt", "--source", &self.source_path, "--vault", &self.vault_path, "--password", &self.password]);
                    }
                }
                if ui.button("Decrypt").clicked() {
                    self.run_command(&["decrypt", "--vault", &self.vault_path, "--dest", &self.dest_path, "--password", &self.password]);
                }
                if ui.button("List Files").clicked() {
                    self.run_command(&["list", "--vault", &self.vault_path, "--password", &self.password]);
                }
            });

            ui.separator();
            ui.label("Output:");
            ui.add(egui::TextEdit::multiline(&mut self.output).desired_rows(10));
        });
    }
}

impl EncryptmanApp {
    fn run_command(&mut self, args: &[&str]) {
        match Command::new("encryptman").args(args).output() {
            Ok(output) => {
                let mut out = String::new();
                out.push_str(&String::from_utf8_lossy(&output.stdout));
                out.push_str(&String::from_utf8_lossy(&output.stderr));
                self.output = out;
            }
            Err(err) => {
                self.output = format!("Failed to run encryptman: {}", err);
            }
        }
    }
}

fn main() {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Encryptman GUI",
        native_options,
        Box::new(|_cc| Box::new(EncryptmanApp::default())),
    );
}
