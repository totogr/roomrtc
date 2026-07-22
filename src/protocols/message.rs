//! Protocolo de mensajes simples con framing y parsing.

use std::collections::HashMap;

/// Estructura que representa un mensaje con tipo y campos.
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: String,
    pub fields: HashMap<String, String>,
}

/// Parsea una linea de texto en un mensaje estructurado.
pub fn parse_message(line: &str) -> Option<Message> {
    let mut parts = line.trim().split('|');

    let msg_type = parts.next()?.to_string();

    let mut fields = HashMap::new();

    for p in parts {
        if let Some((k, v)) = p.split_once('=') {
            fields.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    Some(Message { msg_type, fields })
}

/// Construye una linea de texto a partir de un tipo y campos dados.
pub fn build_message(typ: &str, fields: &[(&str, &str)]) -> String {
    let mut out = String::from(typ);

    for (k, v) in fields {
        out.push('|');
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }

    out
}
