//! Implementacion de la interfaz de usuario de la aplicación RoomRtcApp.

use super::RoomRtcApp;
use crate::app::FileDialogResult;
use crate::app::file_transfer::FileTransferEvent;
use eframe::{Frame, egui};
use rfd::FileDialog;

/// Acciones pendientes disparadas desde la UI
enum PendingAction {
    Accept { stream_id: u16, name: String },
    Reject { stream_id: u16, name: String },
    RemoveEvent { stream_id: u16 },
}

/// Actualiza la interfaz de usuario de la aplicación RoomRtcApp.
pub fn update(app: &mut RoomRtcApp, ctx: &egui::Context, _frame: &mut Frame) {
    // Manejar el resultado del diálogo de selección de archivo
    if let Some(rx) = &app.file_dialog_rx {
        match rx.try_recv() {
            Ok(Some(FileDialogResult::SendFile(path))) => {
                app.file_dialog_rx = None;

                match app.send_file(&path) {
                    Ok(_) => {
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_else(|| "<archivo sin nombre>".into());

                        app.add_log(&format!("Archivo enviado: {}", name));
                    }
                    Err(e) => app.add_log(&format!("Error enviando archivo: {}", e)),
                }
            }

            Ok(Some(FileDialogResult::SaveFile {
                path,
                file,
                stream_id,
            })) => {
                app.file_dialog_rx = None;

                match std::fs::write(&path, &file.data) {
                    Ok(_) => {
                        app.add_log(&format!("Archivo guardado: {}", path.to_string_lossy()));

                        app.file_events.retain(|e| {
                            !matches!(
                                e,
                                FileTransferEvent::Completed { stream_id: id, .. }
                                    if *id == stream_id
                            )
                        });
                    }
                    Err(e) => {
                        app.add_log(&format!("Error guardando archivo: {}", e));
                    }
                }
            }

            Ok(None) => {
                app.file_dialog_rx = None; // cancelado
            }

            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(_) => {
                app.file_dialog_rx = None;
            }
        }
    }

    // Verificar si el hilo receptor configuró la bandera de limpieza
    let should_cleanup = if let Ok(flag) = app.cleanup_flag.lock() {
        *flag
    } else {
        false
    };

    // Poll de eventos de transferencia de archivos
    if let Some(ft) = &mut app.file_transfer {
        let new_events = ft.poll_events();

        for ev in new_events {
            // Si llega Completed, eliminar el Downloading previo
            if let FileTransferEvent::Completed { stream_id, .. } = &ev {
                app.file_events.retain(|e| {
                    !matches!(
                        e,
                        FileTransferEvent::Downloading { stream_id: id, .. } if id == stream_id
                    )
                });
            }

            app.file_events.push(ev);
        }
    }

    // Realizar limpieza de la conexión si es necesario
    if should_cleanup {
        app.cleanup_connection();
        if let Ok(mut flag) = app.cleanup_flag.lock() {
            *flag = false;
        }
        app.add_log("Conexión terminada, app restaurada a estado inicial");
    }

    // Construir la interfaz de usuario
    egui::CentralPanel::default().show(ctx, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("WebRTC");
            ui.separator();

            ui.vertical_centered(|ui| {
                render_local_video(app, ui);
                ui.add_space(20.0);
                render_remote_video(app, ui);
            });

            ui.separator();

            // Controles de llamada y transferencia de archivos
            ui.horizontal(|ui| {
                if ui.button("Colgar").clicked() {
                    app.add_log("Colgando llamada...");
                    app.set_hangup_flag();
                }
                // Botón de mute/unmute audio
                let is_muted = app.audio_muted.lock().map(|m| *m).unwrap_or(false);
                let mute_button_text = if is_muted { "Desmutear" } else { "Mutear" };
                if ui.button(mute_button_text).clicked()
                    && let Ok(mut muted) = app.audio_muted.lock()
                {
                    *muted = !*muted;
                    let new_state = if *muted { "muteado" } else { "desmuteado" };
                    app.add_log(&format!("Audio {}", new_state));
                }
            });

            ui.separator();
            ui.heading("Transferencia de archivos");

            // Enviar archivo
            if ui.button("Enviar archivo").clicked() && app.file_dialog_rx.is_none() {
                let (tx, rx) = std::sync::mpsc::channel();
                app.file_dialog_rx = Some(rx);
                std::thread::spawn(move || {
                    let path = FileDialog::new().pick_file();
                    let _ = tx.send(path.map(FileDialogResult::SendFile));
                });
            }

            ui.separator();
            // Eventos de transferencia
            let mut pending_actions: Vec<PendingAction> = Vec::new();

            if app.file_events.is_empty() {
                ui.label("Sin transferencias activas");
            } else {
                for event in app.file_events.iter() {
                    match event {
                        FileTransferEvent::IncomingOffer {
                            stream_id,
                            metadata,
                        } => {
                            ui.vertical(|ui| {
                                ui.label(format!(
                                    "Archivo entrante: {} ({} bytes)",
                                    metadata.name, metadata.size
                                ));

                                ui.horizontal(|ui| {
                                    if ui.button("Aceptar").clicked() {
                                        pending_actions.push(PendingAction::Accept {
                                            stream_id: *stream_id,
                                            name: metadata.name.clone(),
                                        });
                                    }

                                    if ui.button("Rechazar").clicked() {
                                        pending_actions.push(PendingAction::Reject {
                                            stream_id: *stream_id,
                                            name: metadata.name.clone(),
                                        });
                                        pending_actions.push(PendingAction::RemoveEvent {
                                            stream_id: *stream_id,
                                        });
                                    }
                                });
                            });
                        }

                        FileTransferEvent::Downloading { stream_id, metadata } => {
                            if let Some(ft) = &app.file_transfer
                                && let Some(progress) = ft.get_download_progress(*stream_id)
                            {
                                let current = (progress / 100.0) * metadata.size as f32;
                                ui.vertical(|ui| {
                                    ui.label(format!("Descargando: {}", metadata.name));
                                    ui.add(
                                        egui::ProgressBar::new(progress / 100.0)
                                            .show_percentage()
                                            .text(format!(
                                                "{}/{} bytes",
                                                current,
                                                metadata.size
                                            )),
                                    );
                                });
                            }
                        }

                        FileTransferEvent::Completed { stream_id, file } => {
                            ui.horizontal(|ui| {
                                ui.label(format!(
                                    "Recibido: {} ({} bytes)",
                                    file.metadata.name, file.metadata.size
                                ));
                                if ui.button("Guardar").clicked() && app.file_dialog_rx.is_none() {
                                    let file = file.clone();
                                    let stream_id = *stream_id;
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    app.file_dialog_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let path = FileDialog::new()
                                            .set_file_name(&file.metadata.name)
                                            .save_file();
                                        let _ = tx.send(path.map(|p| FileDialogResult::SaveFile {
                                            path: p,
                                            file: file.clone(),
                                            stream_id,
                                        }));
                                    });
                                }
                            });
                        }

                        FileTransferEvent::Rejected { stream_id, reason } => {
                            ui.label(format!("Transferencia rechazada: {}", reason));
                            pending_actions.push(PendingAction::RemoveEvent {
                                stream_id: *stream_id,
                            });
                        }
                    }
                }
            }

            // Ejecutar acciones pendientes
            for action in pending_actions {
                match action {
                    PendingAction::Accept { stream_id, name } => {
                        if let Some(ft) = &mut app.file_transfer {
                            ft.accept(stream_id);
                            app.pending_accept_file = Some(stream_id);
                            app.file_events.retain(|e| !matches!(
                                e,
                                FileTransferEvent::IncomingOffer { stream_id: id, .. } if *id == stream_id
                            ));
                            let metadata = ft
                                .get_download_metadata(stream_id)
                                .expect("metadata debe existir");
                            app.file_events.push(
                                FileTransferEvent::Downloading {
                                    stream_id,
                                    metadata,
                                }
                            );
                            app.add_log(&format!("Archivo aceptado: {}", name));
                        }
                    }

                    PendingAction::Reject { stream_id, name } => {
                        if let Some(ft) = &mut app.file_transfer {
                            ft.reject(stream_id);
                            app.pending_reject_file = Some(stream_id);
                            app.add_log(&format!("Archivo rechazado: {}", name));
                        }
                    }

                    PendingAction::RemoveEvent { stream_id } => {
                        app.file_events.retain(|e| match e {
                            FileTransferEvent::IncomingOffer { stream_id: id, .. }
                            | FileTransferEvent::Downloading { stream_id: id, .. }
                            | FileTransferEvent::Completed { stream_id: id, .. }
                            | FileTransferEvent::Rejected { stream_id: id, .. } => *id != stream_id,
                        });
                    }
                }
            }

            // Estado general
            if let Some(ft) = &app.file_transfer {
                ui.separator();
                ui.label(format!("Subidas activas: {}", ft.active_uploads_count()));
                ui.label(format!(
                    "Descargas activas: {}",
                    ft.active_downloads_count()
                ));
            }

            ui.separator();

            // Sección de logs RTCP
            ui.collapsing("RTCP Logs", |ui| {
                egui::ScrollArea::vertical()
                    .max_height(150.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if let Ok(logs) = app.rtcp_logs.lock() {
                            for log in logs.iter() {
                                ui.label(log);
                            }
                        } else {
                            ui.label("Error leyendo RTCP logs");
                        }
                    });
            });
        });
    });

    // Solicitar repintado si hay nuevos frames de video
    let should_repaint = app.camera.is_some()
        || app
            .remote_frame
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false);

    if should_repaint {
        ctx.request_repaint();
    }

    // Forzar repintado mientras haya descargas activas
    if let Some(ft) = &app.file_transfer
        && ft.active_downloads_count() > 0
    {
        ctx.request_repaint();
    }
}

/// Renderiza la vista de video local en la interfaz de usuario.
fn render_local_video(app: &mut RoomRtcApp, ui: &mut egui::Ui) {
    let frame_max_width = app.config.ui.frame_max_width;
    let frame_max_height = app.config.ui.frame_max_height;

    ui.vertical(|ui| {
        ui.label("Vista local");
        egui::Frame::dark_canvas(ui.style())
            .fill(egui::Color32::BLACK)
            .show(ui, |ui| {
                ui.set_min_size([frame_max_width, frame_max_height].into());
                ui.set_max_size([frame_max_width, frame_max_height].into());

                let Some(cam_arc) = &app.camera else {
                    ui.centered_and_justified(|ui| ui.label("(Video local)"));
                    return;
                };

                let new_frame = {
                    let Ok(mut cam) = cam_arc.lock() else {
                        ui.centered_and_justified(|ui| ui.label("Error cámara (mutex)"));
                        return;
                    };

                    cam.get_frame()
                };

                if let Some(frame) = new_frame {
                    // Cargar textura solo una vez
                    let tex = app.local_texture.get_or_insert_with(|| {
                        ui.ctx().load_texture(
                            "local_camera",
                            frame.clone(),
                            egui::TextureOptions::LINEAR,
                        )
                    });

                    // Actualizar textura solo con datos nuevos
                    tex.set(frame, egui::TextureOptions::LINEAR);

                    ui.add(
                        egui::Image::new(&*tex)
                            .fit_to_exact_size(egui::Vec2::new(frame_max_width, frame_max_height)),
                    );
                } else {
                    ui.centered_and_justified(|ui| ui.label("Esperando frame..."));
                }
            });
    });
}

/// Renderiza la vista de video remoto en la interfaz de usuario.
fn render_remote_video(app: &mut RoomRtcApp, ui: &mut egui::Ui) {
    let frame_max_width = app.config.ui.frame_max_width;
    let frame_max_height = app.config.ui.frame_max_height;

    ui.vertical(|ui| {
        ui.label("Vista remota");
        egui::Frame::dark_canvas(ui.style())
            .fill(egui::Color32::BLACK)
            .show(ui, |ui| {
                ui.set_min_size([frame_max_width, frame_max_height].into());
                ui.set_max_size([frame_max_width, frame_max_height].into());

                let frame_opt = match app.remote_frame.lock() {
                    Ok(f) => f.clone(),
                    Err(_) => {
                        ui.centered_and_justified(|ui| ui.label("Error remoto"));
                        return;
                    }
                };

                if let Some(frame) = frame_opt {
                    let tex = app.remote_texture.get_or_insert_with(|| {
                        ui.ctx().load_texture(
                            "remote_camera",
                            frame.clone(),
                            egui::TextureOptions::LINEAR,
                        )
                    });

                    tex.set(frame, egui::TextureOptions::LINEAR);

                    ui.add(
                        egui::Image::new(&*tex)
                            .fit_to_exact_size(egui::Vec2::new(frame_max_width, frame_max_height)),
                    );
                } else {
                    ui.centered_and_justified(|ui| ui.label("(Video remoto)"));
                }
            });
    });
}
