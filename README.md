# 🐝 Panal Seguro (Enjambre DevSecOps)

## 🛠️ Arquitectura del Enjambre
El sistema utiliza un pipeline de cuatro agentes especializados:
* **Guardrail:** Filtra intentos de inyección de prompts y asegura la integridad de las peticiones.
* **Arquitecto:** Diseña la topología y estructuras de datos necesarias.
* **Implementador:** Genera código Rust limpio y funcional.
* **SecOps:** Audita el código generado buscando vulnerabilidades.

## 🚀 Inicio Rápido

### Requisitos Previos
* Rust (Edición 2024)
* Una llave de API de DeepSeek

### Configuración
Configura las variables de entorno necesarias para la comunicación segura y el acceso a la IA:

1. Configura tus llaves:
   `export DEEPSEEK_API_KEY="tu_llave"`
   `export PANAL_WS_TOKEN="tu_token"`
   
2. Ejecuta:
   `cargo run`

## 🔒 Seguridad
Código firmado con **Ed25519**.
