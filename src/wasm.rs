//! WebAssembly bindings for the JavaScript API.

use alloc::vec::Vec;

use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm-web")]
pub use wasm_bindgen_rayon::init_thread_pool;

use crate::constants::{Params, SHRINCS_B, SHRINCS_B32, SHRINCS_L};
use crate::shrincs::{self, PublicKey, SecretKey, State};

const PUBLIC_KEY_LEN: usize = 32;
const SECRET_KEY_LEN: usize = 96;
const KEYPAIR_LEN: usize = PUBLIC_KEY_LEN + SECRET_KEY_LEN;
const STATE_LEN: usize = 5;
const SEED_LEN: usize = 48;

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum ParamsType {
    L,
    B,
    B32,
}

#[wasm_bindgen(js_name = publicKeyLen)]
pub fn public_key_len() -> usize {
    PUBLIC_KEY_LEN
}

#[wasm_bindgen(js_name = secretKeyLen)]
pub fn secret_key_len() -> usize {
    SECRET_KEY_LEN
}

#[wasm_bindgen(js_name = keypairLen)]
pub fn keypair_len() -> usize {
    KEYPAIR_LEN
}

#[wasm_bindgen(js_name = stateLen)]
pub fn state_len() -> usize {
    STATE_LEN
}

#[wasm_bindgen(js_name = statelessSignatureLen)]
pub fn stateless_signature_len(params: ParamsType) -> usize {
    match params {
        ParamsType::L => SHRINCS_L::SL_SIZE,
        ParamsType::B => SHRINCS_B::SL_SIZE,
        ParamsType::B32 => SHRINCS_B32::SL_SIZE,
    }
}

#[wasm_bindgen(js_name = preparedStatelessKeyLen)]
pub fn prepared_stateless_key_len(params: ParamsType) -> usize {
    match params {
        ParamsType::L => shrincs::PreparedStatelessKey::<SHRINCS_L>::serialized_len(),
        ParamsType::B => shrincs::PreparedStatelessKey::<SHRINCS_B>::serialized_len(),
        ParamsType::B32 => shrincs::PreparedStatelessKey::<SHRINCS_B32>::serialized_len(),
    }
}

#[wasm_bindgen(js_name = statefulSignatureMaxLen)]
pub fn stateful_signature_max_len(params: ParamsType) -> usize {
    match params {
        ParamsType::L => SHRINCS_L::MAX_SF_SIZE,
        ParamsType::B => SHRINCS_B::MAX_SF_SIZE,
        ParamsType::B32 => SHRINCS_B32::MAX_SF_SIZE,
    }
}

#[wasm_bindgen(js_name = initialState)]
pub fn initial_state() -> Vec<u8> {
    let mut state = Vec::with_capacity(STATE_LEN);
    write_state(&mut state, &State { q: 0, valid: true });
    state
}

#[wasm_bindgen(js_name = stateCounter)]
pub fn state_counter(state: &[u8]) -> Result<u32, JsValue> {
    Ok(read_state(state)?.q)
}

#[wasm_bindgen]
pub fn keygen(params: ParamsType) -> Result<Vec<u8>, JsValue> {
    match params {
        ParamsType::L => keygen_for::<SHRINCS_L>(),
        ParamsType::B => keygen_for::<SHRINCS_B>(),
        ParamsType::B32 => keygen_for::<SHRINCS_B32>(),
    }
}

#[wasm_bindgen(js_name = keypairFromSeed)]
pub fn keypair_from_seed(params: ParamsType, seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    match params {
        ParamsType::L => keypair_from_seed_for::<SHRINCS_L>(seed),
        ParamsType::B => keypair_from_seed_for::<SHRINCS_B>(seed),
        ParamsType::B32 => keypair_from_seed_for::<SHRINCS_B32>(seed),
    }
}

#[wasm_bindgen(js_name = publicKeyFromKeypair)]
pub fn public_key_from_keypair(keypair: &[u8]) -> Result<Vec<u8>, JsValue> {
    if keypair.len() != KEYPAIR_LEN {
        return Err(length_error("keypair", KEYPAIR_LEN, keypair.len()));
    }

    Ok(keypair[..PUBLIC_KEY_LEN].to_vec())
}

#[wasm_bindgen(js_name = secretKeyFromKeypair)]
pub fn secret_key_from_keypair(keypair: &[u8]) -> Result<Vec<u8>, JsValue> {
    if keypair.len() != KEYPAIR_LEN {
        return Err(length_error("keypair", KEYPAIR_LEN, keypair.len()));
    }

    Ok(keypair[PUBLIC_KEY_LEN..].to_vec())
}

#[wasm_bindgen(js_name = signStateless)]
pub fn sign_stateless(
    params: ParamsType,
    message: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    match params {
        ParamsType::L => sign_stateless_for::<SHRINCS_L>(message, secret_key),
        ParamsType::B => sign_stateless_for::<SHRINCS_B>(message, secret_key),
        ParamsType::B32 => sign_stateless_for::<SHRINCS_B32>(message, secret_key),
    }
}

#[wasm_bindgen(js_name = signStatelessPrepare)]
pub fn sign_stateless_prepare(params: ParamsType, secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    match params {
        ParamsType::L => sign_stateless_prepare_for::<SHRINCS_L>(secret_key),
        ParamsType::B => sign_stateless_prepare_for::<SHRINCS_B>(secret_key),
        ParamsType::B32 => sign_stateless_prepare_for::<SHRINCS_B32>(secret_key),
    }
}

#[wasm_bindgen(js_name = signStatelessWithPrepare)]
pub fn sign_stateless_with_prepare(
    params: ParamsType,
    message: &[u8],
    secret_key: &[u8],
    prepared_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    match params {
        ParamsType::L => {
            sign_stateless_with_prepare_for::<SHRINCS_L>(message, secret_key, prepared_key)
        }
        ParamsType::B => {
            sign_stateless_with_prepare_for::<SHRINCS_B>(message, secret_key, prepared_key)
        }
        ParamsType::B32 => {
            sign_stateless_with_prepare_for::<SHRINCS_B32>(message, secret_key, prepared_key)
        }
    }
}

#[wasm_bindgen(js_name = signStateful)]
pub fn sign_stateful(
    params: ParamsType,
    message: &[u8],
    secret_key: &[u8],
    state: &[u8],
) -> Result<Vec<u8>, JsValue> {
    match params {
        ParamsType::L => sign_stateful_for::<SHRINCS_L>(message, secret_key, state),
        ParamsType::B => sign_stateful_for::<SHRINCS_B>(message, secret_key, state),
        ParamsType::B32 => sign_stateful_for::<SHRINCS_B32>(message, secret_key, state),
    }
}

#[wasm_bindgen(js_name = stateFromStatefulSignResult)]
pub fn state_from_stateful_sign_result(result: &[u8]) -> Result<Vec<u8>, JsValue> {
    if result.len() < STATE_LEN {
        return Err(length_error_at_least(
            "stateful_sign_result",
            STATE_LEN,
            result.len(),
        ));
    }

    Ok(result[..STATE_LEN].to_vec())
}

#[wasm_bindgen(js_name = signatureFromStatefulSignResult)]
pub fn signature_from_stateful_sign_result(result: &[u8]) -> Result<Vec<u8>, JsValue> {
    if result.len() < STATE_LEN {
        return Err(length_error_at_least(
            "stateful_sign_result",
            STATE_LEN,
            result.len(),
        ));
    }

    Ok(result[STATE_LEN..].to_vec())
}

#[wasm_bindgen]
pub fn verify(
    params: ParamsType,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JsValue> {
    match params {
        ParamsType::L => verify_for::<SHRINCS_L>(message, signature, public_key),
        ParamsType::B => verify_for::<SHRINCS_B>(message, signature, public_key),
        ParamsType::B32 => verify_for::<SHRINCS_B32>(message, signature, public_key),
    }
}

#[wasm_bindgen(js_name = verifyStateful)]
pub fn verify_stateful(
    params: ParamsType,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JsValue> {
    match params {
        ParamsType::L => verify_stateful_for::<SHRINCS_L>(message, signature, public_key),
        ParamsType::B => verify_stateful_for::<SHRINCS_B>(message, signature, public_key),
        ParamsType::B32 => verify_stateful_for::<SHRINCS_B32>(message, signature, public_key),
    }
}

fn keygen_for<P: Params>() -> Result<Vec<u8>, JsValue> {
    let mut public_key = PublicKey::default();
    let mut secret_key = SecretKey::default();
    let mut state = State::default();

    shrincs::key_gen::<P>(&mut public_key, &mut secret_key, &mut state).map_err(operation_error)?;

    let mut keypair = Vec::with_capacity(KEYPAIR_LEN);
    write_public_key(&mut keypair, &public_key);
    write_secret_key(&mut keypair, &secret_key);
    Ok(keypair)
}

fn keypair_from_seed_for<P: Params>(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let seed = read_seed(seed)?;
    let mut public_key = PublicKey::default();
    let mut secret_key = SecretKey::default();
    let mut state = State::default();

    shrincs::restore::<P>(&seed, &mut public_key, &mut secret_key, &mut state);

    let mut keypair = Vec::with_capacity(KEYPAIR_LEN);
    write_public_key(&mut keypair, &public_key);
    write_secret_key(&mut keypair, &secret_key);
    Ok(keypair)
}

fn read_seed(bytes: &[u8]) -> Result<[u8; SEED_LEN], JsValue> {
    if bytes.len() != SEED_LEN {
        return Err(length_error("seed", SEED_LEN, bytes.len()));
    }

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

fn sign_stateless_for<P: Params>(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret_key = read_secret_key(secret_key)?;
    shrincs::sign_stateless::<P>(message, &secret_key).map_err(operation_error)
}

fn sign_stateless_prepare_for<P: Params>(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret_key = read_secret_key(secret_key)?;
    Ok(shrincs::sign_stateless_prepare::<P>(&secret_key).to_bytes())
}

fn sign_stateless_with_prepare_for<P: Params>(
    message: &[u8],
    secret_key: &[u8],
    prepared_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let secret_key = read_secret_key(secret_key)?;
    let prepared_key = shrincs::PreparedStatelessKey::<P>::from_bytes(prepared_key)
        .ok_or_else(|| JsValue::from_str("invalid prepared stateless key"))?;
    shrincs::sign_stateless_with_prepare::<P>(message, &secret_key, &prepared_key)
        .map_err(operation_error)
}

fn sign_stateful_for<P: Params>(
    message: &[u8],
    secret_key: &[u8],
    state: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut secret_key = read_secret_key(secret_key)?;
    let mut state = read_state(state)?;
    let signature = shrincs::sign_stateful::<P>(message, &mut secret_key, &mut state)
        .map_err(operation_error)?;

    let mut result = Vec::with_capacity(STATE_LEN + signature.len());
    write_state(&mut result, &state);
    result.extend_from_slice(&signature);
    Ok(result)
}

fn verify_for<P: Params>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JsValue> {
    let public_key = read_public_key(public_key)?;
    Ok(shrincs::verify::<P>(message, signature, &public_key))
}

fn verify_stateful_for<P: Params>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JsValue> {
    let public_key = read_public_key(public_key)?;
    Ok(shrincs::verify_stateful::<P>(
        message,
        signature,
        &public_key,
    ))
}

fn write_public_key(out: &mut Vec<u8>, public_key: &PublicKey) {
    out.extend_from_slice(&public_key.seed);
    out.extend_from_slice(&public_key.root);
}

fn write_secret_key(out: &mut Vec<u8>, secret_key: &SecretKey) {
    out.extend_from_slice(&secret_key.seed);
    out.extend_from_slice(&secret_key.prf);
    out.extend_from_slice(&secret_key.sf);
    out.extend_from_slice(&secret_key.sl);
    write_public_key(out, &secret_key.pk);
}

fn write_state(out: &mut Vec<u8>, state: &State) {
    out.extend_from_slice(&state.q.to_le_bytes());
    out.push(u8::from(state.valid));
}

fn read_public_key(bytes: &[u8]) -> Result<PublicKey, JsValue> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(length_error("public_key", PUBLIC_KEY_LEN, bytes.len()));
    }

    let mut public_key = PublicKey::default();
    public_key.seed.copy_from_slice(&bytes[..16]);
    public_key.root.copy_from_slice(&bytes[16..32]);
    Ok(public_key)
}

fn read_secret_key(bytes: &[u8]) -> Result<SecretKey, JsValue> {
    if bytes.len() != SECRET_KEY_LEN {
        return Err(length_error("secret_key", SECRET_KEY_LEN, bytes.len()));
    }

    let mut secret_key = SecretKey::default();
    secret_key.seed.copy_from_slice(&bytes[..16]);
    secret_key.prf.copy_from_slice(&bytes[16..32]);
    secret_key.sf.copy_from_slice(&bytes[32..48]);
    secret_key.sl.copy_from_slice(&bytes[48..64]);
    secret_key.pk = read_public_key(&bytes[64..])?;
    Ok(secret_key)
}

fn read_state(bytes: &[u8]) -> Result<State, JsValue> {
    if bytes.len() != STATE_LEN {
        return Err(length_error("state", STATE_LEN, bytes.len()));
    }

    let mut q = [0u8; 4];
    q.copy_from_slice(&bytes[..4]);
    let valid = match bytes[4] {
        0 => false,
        1 => true,
        value => {
            return Err(JsValue::from_str(&alloc::format!(
                "invalid state flag: {value}"
            )));
        }
    };

    Ok(State {
        q: u32::from_le_bytes(q),
        valid,
    })
}

fn operation_error(error: shrincs::Error) -> JsValue {
    JsValue::from_str(&alloc::format!("SHRINCS operation failed: {error:?}"))
}

fn length_error(name: &str, expected: usize, actual: usize) -> JsValue {
    JsValue::from_str(&alloc::format!(
        "invalid {name} length: expected {expected}, got {actual}"
    ))
}

fn length_error_at_least(name: &str, expected: usize, actual: usize) -> JsValue {
    JsValue::from_str(&alloc::format!(
        "invalid {name} length: expected at least {expected}, got {actual}"
    ))
}
