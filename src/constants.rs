//! Common constants and hard limits

/// Maximum cipher key length supported
pub const MAX_KEY_LEN: usize = 32;
/// Maximum cipher tag length supported
pub const MAX_TAG_LEN: usize = 16;
/// Maximum Noise message length
pub const MAX_MESSAGE_LEN: usize = 65535;
/// PSK token length
pub const PSK_LEN: usize = 32;
/// How many PSKs a handshake pattern can have
pub const MAX_PSKS: usize = 4;
/// How many tokens a single handshake message can include
pub const MAX_TOKENS_PER_HS_MESSAGE: usize = 8;
/// How many handshake messages a party can send
pub const MAX_HS_MESSAGES_PER_ROLE: usize = 8;
/// Hash constant to mix into inner handshake of a dual layer handshake
pub const HYBRID_DUAL_LAYER_HANDSHAKE_DOMAIN: &[u8] = b"clatter.hybrid_dual_layer.outer";
