//! Криптоядро на Rust. Python видит его как модуль `ecp._core`.
//!
//! Форматы (ТЗ, п. 4 «Входные и выходные данные»), байты как в СТБ
//! (числа записываются «от младших к старшим», little-endian):
//!   личный ключ d   - 32 байта
//!   открытый ключ Q - 64 байта (<x>256 || <y>256)
//!   подпись S       - 48 байт (3l, l = 128)
//!
//! Крейт bign256 работает с big-endian, поэтому на границе модуля
//! выполняется разворот байт (см. `rev`).

use ::belt_hash::{BeltHash, Digest};
use belt_block::belt_block_raw;
use bign256::dsa::signature::Verifier;
use bign256::dsa::{Signature, VerifyingKey};
use bign256::elliptic_curve::sec1::ToEncodedPoint;
use bign256::SecretKey;
use num_bigint::BigUint;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::OsRng;

const PRIVATE_KEY_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 64;
const SIGNATURE_LEN: usize = 48;
const HASH_LEN: usize = 32;
const MAX_BRNG_BLOCKS: usize = 1 << 16;

/// OID(belt-hash) в DER: {1 2 112 0 2 0 34 101 31 81} (СТБ 34.101.45, п. 4.2.5).
const OID_BELT_HASH: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
];

/// Порядок q группы точек bign-curve256v1 (СТБ 34.101.45, табл. Б.1).
fn order_q() -> BigUint {
    let mut q = [0xFFu8; 32];
    q[..16].copy_from_slice(&[
        0x07, 0x66, 0x3D, 0x26, 0x99, 0xBF, 0x5A, 0x7E, 0xFC, 0x4D, 0xFB, 0x0D, 0xD6, 0x8E, 0x5C,
        0xD9,
    ]);
    BigUint::from_bytes_le(&q)
}

fn in_range(x: &BigUint, q: &BigUint) -> bool {
    *x != BigUint::from(0u8) && x < q
}

/// Байты -> слова u32 (little-endian), как в BelT.
fn words<const N: usize>(b: &[u8]) -> [u32; N] {
    let mut w = [0u32; N];
    for i in 0..N {
        w[i] = u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    w
}

fn block_to_bytes(w: &[u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].to_le_bytes());
    }
    out
}

/// Генерация одноразового личного ключа k (СТБ 34.101.45, п. 6.3.3), l = 128 (n = 2).
/// d - личный ключ, h - хэш сообщения H, t - произвольное слово (по умолчанию пустое).
fn gen_k_inner(d: &[u8], h: &[u8; HASH_LEN], t: &[u8]) -> Result<[u8; 32], &'static str> {
    let q = order_q();
    // 2: theta <- belt-hash(OID(h) || <d> || t)
    let theta_bytes = belt(&[&OID_BELT_HASH, d, t]);
    let theta: [u32; 8] = words::<8>(&theta_bytes);
    // 3: r <- H, r = r1 || r2
    let mut r1 = [0u8; 16];
    let mut r2 = [0u8; 16];
    r1.copy_from_slice(&h[..16]);
    r2.copy_from_slice(&h[16..]);
    let mut i: u128 = 1;
    loop {
        // a) s <- r1
        let s = r1;
        // d) r1 <- belt-block(s, theta) xor r2 xor <i>_128
        let e = block_to_bytes(&belt_block_raw(words::<4>(&s), &theta));
        let ib = i.to_le_bytes();
        let mut nr1 = [0u8; 16];
        for j in 0..16 {
            nr1[j] = e[j] ^ r2[j] ^ ib[j];
        }
        // e) r2 <- s
        r1 = nr1;
        r2 = s;
        // f) i кратно 2n = 4 и r in {1..q-1} -> k <- r
        if i % 4 == 0 {
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(&r1);
            k[16..].copy_from_slice(&r2);
            if in_range(&BigUint::from_bytes_le(&k), &q) {
                return Ok(k);
            }
        }
        i += 1;
        if i > (1 << 20) {
            return Err("Ошибка: не удалось сгенерировать одноразовый ключ");
        }
    }
}

/// Выработка ЭЦП по хэшу H с заданным одноразовым ключом k (СТБ 34.101.45, п. 7.1.3).
fn sign_with_k_inner(d: &[u8], k: &[u8], h: &[u8; HASH_LEN]) -> Result<[u8; SIGNATURE_LEN], &'static str> {
    let q = order_q();
    let dv = BigUint::from_bytes_le(d);
    let kv = BigUint::from_bytes_le(k);
    if !in_range(&dv, &q) {
        return Err("Ошибка: личный ключ вне допустимого диапазона");
    }
    if !in_range(&kv, &q) {
        return Err("Ошибка: одноразовый ключ вне допустимого диапазона");
    }
    // 3: R <- kG
    let secret_k = SecretKey::from_slice(&rev(k)).map_err(|_| "Ошибка: неверный одноразовый ключ")?;
    let r_point = public_key_std(&secret_k);
    let xr = &r_point[..32];
    // 4: S0 <- <belt-hash(OID(h) || <R>_2l || H)>_l
    let s0_full = belt(&[&OID_BELT_HASH, xr, h]);
    let s0 = &s0_full[..16];
    // 5: S1 <- <(k - H - (S0 + 2^l) d) mod q>_2l
    let hv = BigUint::from_bytes_le(h);
    let s0v = BigUint::from_bytes_le(s0);
    let two_l = BigUint::from(1u8) << 128usize;
    let t = (&hv + (&s0v + &two_l) * &dv) % &q;
    let s1v = (&kv + &q - t) % &q;
    let mut s1 = s1v.to_bytes_le();
    s1.resize(32, 0);
    // 6: S <- S0 || S1
    let mut out = [0u8; SIGNATURE_LEN];
    out[..16].copy_from_slice(s0);
    out[16..].copy_from_slice(&s1);
    Ok(out)
}

fn err(msg: &str) -> PyErr {
    PyValueError::new_err(msg.to_string())
}

fn rev(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// belt-hash от конкатенации нескольких частей.
fn belt(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = BeltHash::new();
    for p in parts {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// HMAC на belt-hash (СТБ 34.101.47, п. 6.1): длина блока b = 32 байта.
fn hmac_hbelt(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    const B: usize = 32;
    let mut t = [0u8; B];
    if key.len() <= B {
        t[..key.len()].copy_from_slice(key);
    } else {
        t.copy_from_slice(&belt(&[key]));
    }
    let mut ipad = [0u8; B];
    let mut opad = [0u8; B];
    for i in 0..B {
        ipad[i] = t[i] ^ 0x36;
        opad[i] = t[i] ^ 0x5C;
    }
    let inner = belt(&[&ipad, data]);
    belt(&[&opad, &inner])
}

/// Увеличение 256-битного числа (little-endian) на 1 по модулю 2^256.
fn inc_le(s: &mut [u8; HASH_LEN]) {
    for b in s.iter_mut() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            break;
        }
    }
}

/// Открытый ключ в формате СТБ (64 байта) по секретному ключу крейта.
fn public_key_std(secret: &SecretKey) -> Vec<u8> {
    let point = secret.public_key().to_encoded_point(false);
    let b = point.as_bytes(); // 0x04 || x || y (big-endian), 65 байт
    let mut q = Vec::with_capacity(PUBLIC_KEY_LEN);
    q.extend(rev(&b[1..33]));
    q.extend(rev(&b[33..65]));
    q
}

fn secret_from_std(private_key: &[u8]) -> PyResult<SecretKey> {
    if private_key.len() != PRIVATE_KEY_LEN {
        return Err(err("Ошибка: неверный формат ключа"));
    }
    SecretKey::from_slice(&rev(private_key)).map_err(|_| err("Ошибка: личный ключ вне допустимого диапазона"))
}

/// Хэш belt-hash (СТБ 34.101.31) от произвольных байт. Возвращает 32 байта.
#[pyfunction]
#[pyo3(name = "belt_hash")]
fn py_belt_hash<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &belt(&[data]))
}

/// Имитовставка HMAC-hbelt (СТБ 34.101.47, п. 6.1). Ключ любой длины.
#[pyfunction]
#[pyo3(name = "hmac_hbelt")]
fn py_hmac_hbelt<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &hmac_hbelt(key, data))
}

/// Генерация псевдослучайных чисел в режиме счетчика, brng-ctr-hbelt
/// (СТБ 34.101.47, п. 6.2). key, iv - по 32 байта, n - число блоков по 32 байта.
/// additional - необязательные дополнительные данные X (n*32 байт), по умолчанию нули.
#[pyfunction]
#[pyo3(name = "brng_ctr", signature = (key, iv, n, additional=None))]
fn py_brng_ctr<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    n: usize,
    additional: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != HASH_LEN {
        return Err(err("Ошибка: ключ генератора должен быть 32 байта"));
    }
    if iv.len() != HASH_LEN {
        return Err(err("Ошибка: синхропосылка должна быть 32 байта"));
    }
    if n == 0 || n > MAX_BRNG_BLOCKS {
        return Err(err("Ошибка: недопустимое число блоков"));
    }
    if let Some(x) = additional {
        if x.len() != n * HASH_LEN {
            return Err(err("Ошибка: длина дополнительных данных должна быть 32*n"));
        }
    }
    let zero = [0u8; HASH_LEN];
    let mut s = [0u8; HASH_LEN];
    s.copy_from_slice(iv);
    let mut r = [0u8; HASH_LEN];
    for (ri, si) in r.iter_mut().zip(iv.iter()) {
        *ri = !*si; // r = S xor 1^{2l}
    }
    let mut out = Vec::with_capacity(n * HASH_LEN);
    for i in 0..n {
        let xi: &[u8] = match additional {
            Some(x) => &x[i * HASH_LEN..(i + 1) * HASH_LEN],
            None => &zero,
        };
        let y = belt(&[key, &s, xi, &r]);
        out.extend_from_slice(&y);
        inc_le(&mut s);
        for (ri, yi) in r.iter_mut().zip(y.iter()) {
            *ri ^= *yi;
        }
    }
    Ok(PyBytes::new(py, &out))
}

/// Открытый ключ Q (64 байта) по личному ключу d (32 байта): Q = d*G.
#[pyfunction]
#[pyo3(name = "derive_public_key")]
fn py_derive_public_key<'py>(py: Python<'py>, private_key: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let secret = secret_from_std(private_key)?;
    Ok(PyBytes::new(py, &public_key_std(&secret)))
}

/// Генерация пары ключей на кривой bign-curve256v1. Возвращает (d, Q): 32 и 64 байта.
#[pyfunction]
#[pyo3(name = "generate_keypair")]
fn py_generate_keypair<'py>(py: Python<'py>) -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
    let secret = SecretKey::random(&mut OsRng);
    let d = rev(&secret.to_bytes());
    let q = public_key_std(&secret);
    (PyBytes::new(py, &d), PyBytes::new(py, &q))
}

/// Одноразовый ключ k по п. 6.3.3 (личный ключ d, хэш H, необязательное слово t).
#[pyfunction]
#[pyo3(name = "gen_k", signature = (private_key, hash, t=None))]
fn py_gen_k<'py>(
    py: Python<'py>,
    private_key: &[u8],
    hash: &[u8],
    t: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    if private_key.len() != PRIVATE_KEY_LEN {
        return Err(err("Ошибка: неверный формат ключа"));
    }
    if hash.len() != HASH_LEN {
        return Err(err("Ошибка: хэш должен быть 32 байта"));
    }
    let mut h = [0u8; HASH_LEN];
    h.copy_from_slice(hash);
    let k = gen_k_inner(private_key, &h, t.unwrap_or(&[])).map_err(err)?;
    Ok(PyBytes::new(py, &k))
}

/// Подпись хэша H с явно заданным одноразовым ключом k (для проверки по стандарту).
#[pyfunction]
#[pyo3(name = "sign_hash_with_k")]
fn py_sign_hash_with_k<'py>(
    py: Python<'py>,
    private_key: &[u8],
    k: &[u8],
    hash: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if private_key.len() != PRIVATE_KEY_LEN || k.len() != PRIVATE_KEY_LEN {
        return Err(err("Ошибка: неверный формат ключа"));
    }
    if hash.len() != HASH_LEN {
        return Err(err("Ошибка: хэш должен быть 32 байта"));
    }
    let mut h = [0u8; HASH_LEN];
    h.copy_from_slice(hash);
    let s = sign_with_k_inner(private_key, k, &h).map_err(err)?;
    Ok(PyBytes::new(py, &s))
}

/// Выработка ЭЦП сообщения `message` личным ключом `private_key` (32 байта).
/// Одноразовый ключ строится по п. 6.3.3 (детерминированно). Возвращает S (48 байт).
#[pyfunction]
#[pyo3(name = "sign")]
fn py_sign<'py>(
    py: Python<'py>,
    private_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if private_key.len() != PRIVATE_KEY_LEN {
        return Err(err("Ошибка: неверный формат ключа"));
    }
    let h = belt(&[message]);
    let k = gen_k_inner(private_key, &h, &[]).map_err(err)?;
    let s = sign_with_k_inner(private_key, &k, &h).map_err(err)?;
    Ok(PyBytes::new(py, &s))
}

/// Проверка ЭЦП. Возвращает True/False (ДА/НЕТ).
/// Некорректные входные данные (длины, диапазоны) -> ValueError.
#[pyfunction]
#[pyo3(name = "verify")]
fn py_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(err("Ошибка: неверный формат ключа"));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(err("Ошибка: неверная длина подписи (|S| != 3l)"));
    }
    let mut sec1 = Vec::with_capacity(PUBLIC_KEY_LEN + 1);
    sec1.push(0x04);
    sec1.extend(rev(&public_key[..32]));
    sec1.extend(rev(&public_key[32..]));
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| err("Ошибка: открытый ключ не принадлежит кривой"))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| err("Ошибка: подпись вне допустимого диапазона (S1 >= q)"))?;
    Ok(verifying_key.verify(message, &sig).is_ok())
}

/// Версия криптоядра (для проверки, что модуль подключился).
#[pyfunction]
fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_belt_hash, m)?)?;
    m.add_function(wrap_pyfunction!(py_hmac_hbelt, m)?)?;
    m.add_function(wrap_pyfunction!(py_brng_ctr, m)?)?;
    m.add_function(wrap_pyfunction!(py_derive_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(py_gen_k, m)?)?;
    m.add_function(wrap_pyfunction!(py_sign_hash_with_k, m)?)?;
    m.add_function(wrap_pyfunction!(py_sign, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify, m)?)?;
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    Ok(())
}
