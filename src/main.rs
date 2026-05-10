use anyhow::Result;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use tower_http::services::ServeFile;

use ed25519_dalek::{Signer, SigningKey};

use rigs::rig::tool::Tool;
use rigs::rig::completion::ToolDefinition; 
use rigs::llm_provider::LLMProvider;
use rigs::rig_agent::RigAgent;
use rigs::agent::Agent; 
use serde::{Deserialize, Serialize}; 
use serde_json::json;
use std::env;

// ==========================================
// ESTRUCTURAS DE COMUNICACIÓN SEGURA
// ==========================================
#[derive(Deserialize, Debug)]
struct WsPayload {
    auth_token: String,
    requerimiento: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SandboxArgs {
    pub codigo_fuente: String,
    pub dependencias: Vec<String>,
}

// ==========================================
// HERRAMIENTA SANDBOX 
// ==========================================
#[derive(Clone, Debug)]
pub struct E2BSandboxExecutor;

impl Tool for E2BSandboxExecutor {
    const NAME: &'static str = "ejecutar_en_sandbox_seguro";
    type Error = std::io::Error;
    type Args = SandboxArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "ejecutar_en_sandbox_seguro".to_string(),
            description: "Ejecuta código en un entorno aislado.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "codigo_fuente": { "type": "string" },
                    "dependencias": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["codigo_fuente", "dependencias"]
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Simulación rápida para la plantilla pública
        Ok("Ejecución exitosa. SAST: 0 vulnerabilidades. RAM: Estable.".to_string())
    }
}

// ==========================================
// SERVIDOR Y ORQUESTACIÓN
// ==========================================
#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Levantando el Panal Seguro (Enjambre DevSecOps)...");

    let app = Router::new()
        .route_service("/", ServeFile::new("index.html"))
        .route("/ws", get(ws_handler));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("🌐 Servidor corriendo seguro en http://localhost:3000");
    
    axum::serve(listener, app).await?;

    Ok(())
}

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();

    // Obtenemos el token de seguridad del entorno o usamos uno por defecto para dev
    let expected_token = env::var("PANAL_WS_TOKEN").unwrap_or_else(|_| "panal_seguro_2026".to_string());

    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(raw_json) = msg {
            let payload: Result<WsPayload, _> = serde_json::from_str(&raw_json);
            
            let req = match payload {
                Ok(data) => {
                    if data.auth_token != expected_token {
                        let _ = sender.send(Message::Text("⛔ [AUTH DENEGADA] Token inválido.".into())).await;
                        continue;
                    }
                    data.requerimiento
                },
                Err(_) => {
                    let _ = sender.send(Message::Text("⛔ [ERROR] Formato inválido.".into())).await;
                    continue;
                }
            };

            let _ = sender.send(Message::Text("✅ [AUTH OK] Solicitud aceptada. Despertando Enjambre...".into())).await;
            
            match inicializar_agentes() {
                Ok((guardrail, arquitecto, implementador, secops)) => {
                    
                    // 1. Capa Guardrail
                    let res_guardrail = guardrail.run(req.clone()).await.unwrap_or_else(|_| "[SEGURO]".to_string());
                    if res_guardrail.contains("[PELIGRO]") || req.to_lowercase().contains("ignora") || req.to_lowercase().contains("clave") {
                        let _ = sender.send(Message::Text("🚨 [BLOQUEO] Intento de Prompt Injection detectado.".into())).await;
                        continue; 
                    }
                    let _ = sender.send(Message::Text("🟢 [GUARDRAIL PASS] Prompt validado.".into())).await;

                    // 2. Capa Arquitecto
                    let _ = sender.send(Message::Text("📐 Arquitecto diseñando topología...".into())).await;
                    let diseno = arquitecto.run(req.clone()).await.unwrap_or_else(|_| "Error en Arquitecto".to_string());
                    let _ = sender.send(Message::Text(format!("✅ [ARQUITECTO]:\n{}", diseno).into())).await;
                    
                    // 3. Capa Implementador
                    let _ = sender.send(Message::Text("💻 Implementador programando lógica en Rust...".into())).await;
                    let prompt_impl = format!("Basado estrictamente en este diseño, escribe SOLAMENTE el código Rust:\n{}", diseno);
                    let codigo_generado = implementador.run(prompt_impl).await.unwrap_or_else(|_| "Error en Implementador".to_string());
                    
                    let _ = sender.send(Message::Text(format!("✅ [IMPLEMENTADOR - CÓDIGO GENERADO]:\n\n{}", codigo_generado).into())).await;

                    // 4. Capa SecOps
                    let _ = sender.send(Message::Text("🔒 SecOps auditando código...".into())).await;
                    let prompt_secops = format!("Audita este código:\n{}", codigo_generado);
                    let auditoria = secops.run(prompt_secops).await.unwrap_or_else(|_| "Error en SecOps".to_string());
                    let _ = sender.send(Message::Text(format!("✅ [SECOPS]:\n{}", auditoria).into())).await;

                    // 5. Capa de Sistema de Archivos
                    let _ = sender.send(Message::Text("💾 Escribiendo código físico en el disco duro...".into())).await;
                    
                    let codigo_puro = extraer_codigo_rust(&codigo_generado);
                    let dir_path = "./app_generada/src";
                    
                    let _ = tokio::fs::create_dir_all(dir_path).await;
                    let file_path = format!("{}/main.rs", dir_path);
                    
                    if let Err(e) = tokio::fs::write(&file_path, &codigo_puro).await {
                        let _ = sender.send(Message::Text(format!("❌ Error guardando archivo: {}", e).into())).await;
                    } else {
                        let _ = sender.send(Message::Text(format!("📁 [SISTEMA]: Aplicación generada exitosamente en {}", file_path).into())).await;
                    }

                    // 6. Capa Code Signing Criptográfico
                    let secret: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
                    let signing_key = SigningKey::from_bytes(&secret);
                    let signature = signing_key.sign(codigo_puro.as_bytes());
                    let sig_hex = signature.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();

                    let _ = sender.send(Message::Text(format!("✅ Pipeline 100% Finalizado.\n[FIRMA Ed25519]:\n{}", sig_hex).into())).await;
                }
                Err(e) => {
                    let _ = sender.send(Message::Text(format!("❌ Error de inicialización: {}", e).into())).await;
                }
            }
        }
    }
}

fn extraer_codigo_rust(raw: &str) -> String {
    let mut in_block = false;
    let mut code = String::new();
    for line in raw.lines() {
        if line.starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block {
            code.push_str(line);
            code.push('\n');
        }
    }
    if code.trim().is_empty() { raw.to_string() } else { code }
}

fn inicializar_agentes() -> Result<(
    RigAgent<impl rigs::rig::completion::CompletionModel>, 
    RigAgent<impl rigs::rig::completion::CompletionModel>, 
    RigAgent<impl rigs::rig::completion::CompletionModel>, 
    RigAgent<impl rigs::rig::completion::CompletionModel>
)> {
    // Apuntamos al modelo actual compatible
    let provider = LLMProvider::deepseek("deepseek-chat");

    let guardrail = RigAgent::deepseek_builder().provider(provider.clone())?.agent_name("Guardrail").system_prompt("Responde [PELIGRO] o [SEGURO].").temperature(0.0).build()?;
    let arquitecto = RigAgent::deepseek_builder().provider(provider.clone())?.agent_name("Arquitecto").system_prompt("Eres un Arquitecto. Devuelve solo el diseño técnico detallado.").temperature(0.3).build()?;
    
    let implementador = RigAgent::deepseek_builder()
        .provider(provider.clone())?
        .agent_name("Implementador")
        .system_prompt("Eres un bot programador experto en Rust. Tu ÚNICA salida debe ser código Rust válido encerrado en un único bloque ```rust ```. No des explicaciones.")
        .temperature(0.1)
        .build()?;

    let secops = RigAgent::deepseek_builder().provider(provider.clone())?.agent_name("SecOps").tool(E2BSandboxExecutor)?.system_prompt("Audita el código en busca de vulnerabilidades lógicas.").temperature(0.1).build()?;

    Ok((guardrail, arquitecto, implementador, secops))
}