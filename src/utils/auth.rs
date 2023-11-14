use anyhow::Error;
use hkdf::Hkdf;
use jsonwebtoken::{encode, EncodingKey, Header};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand_core::OsRng; // requires 'getrandom' feature
use redis::Commands;
use serde::{Deserialize, Serialize};

pub fn bridge_generate_pk() -> (Vec<u8>, EphemeralSecret) {
    let bridge_secret = EphemeralSecret::random(&mut OsRng);
    let bridge_pk_bytes = EncodedPoint::from(bridge_secret.public_key()).to_bytes();
    // println!("B PK: {:#?}",bridge_pk_bytes);
    (bridge_pk_bytes.to_vec(), bridge_secret)
}

pub async fn generate_sk(pk_bytes: Vec<u8>, sk_bytes: EphemeralSecret) -> Vec<u8> {
    let public = PublicKey::from_sec1_bytes(&pk_bytes).expect("Public Key Invalid");

    let shared_key = sk_bytes.diffie_hellman(&public);
    let shared: Vec<u8> = shared_key.raw_secret_bytes().to_vec();

    let client = redis::Client::open("redis://127.0.0.1:6379").expect("Open Connection failed");
    let mut con = client.get_connection().expect("Connection failed");

    let output_length = 32;
    let hkdf = Hkdf::<sha2::Sha256>::new(None, shared.as_slice());
    let info = &pk_bytes;
    // Expand the shared key using the provided info and desired output length
    let mut okm = vec![0u8; output_length];
    let _ = hkdf.expand(info, &mut okm);

    let _: () = con
        .set(pk_bytes.clone(), shared.to_vec())
        .expect("Failed setting key value");

    // let k: Vec<u8> = con.get(pk_bytes.clone()).expect("Key value not found");
    // println!("Key is {:#?}", k);

    // println!("SK: {:?}", shared);
    // okm.clone()
    shared.to_vec()
}

pub async fn get_pk(origin_pk: &[u8]) -> Result<Vec<u8>, Error> {
    // let pk = origin_pk.clone();

    #[derive(Debug, Serialize)]
    struct Pk {
        pk: Vec<u8>,
    }
    let payload = Pk {
        pk: origin_pk.to_vec(),
    };
    let payload_json = serde_json::to_string(&payload).expect("Parsing to string error");

    let client = reqwest::Client::new();
    let hsm_domain = match dotenvy::var("HSM_DOMAIN") {
        Ok(path) => path,
        Err(err) => return Err(err.into()),
    };
    let hsm_port = match dotenvy::var("HSM_PORT") {
        Ok(path) => path,
        Err(err) => return Err(err.into()),
    };
    let hsm_pk_path = match dotenvy::var("HSM_PK_PATH") {
        Ok(path) => path,
        Err(err) => return Err(err.into()),
    };
    let jwt_token = match generate_jwt_key().await {
        Ok(token) => token,
        Err(err) => return Err(err),
    };
    // let body = serde_json::to_string(&origin_pk).expect("Failed parsing origin_pk");
    let res = client
        .get(format!("{}:{}/{}", hsm_domain, hsm_port, hsm_pk_path))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", jwt_token),
        )
        .body(payload_json)
        .send()
        .await?;
    let res_data: KeyPayload = res.json().await?;

    #[derive(Debug, Deserialize)]
    struct KeyPayload {
        status: String,
        data: Vec<u8>,
    }
    println!("Response: {:#?}", res_data);
    let pk_bytes = if res_data.status == "success" {
        res_data.data
    } else {
        return Err(Error::msg("PK Not Found"));
    };
    Ok(pk_bytes)
}

pub async fn generate_jwt_key() -> Result<String, Error> {
    let public_key: String = match dotenvy::var("PUBLIC_KEY") {
        Ok(p) => p,
        Err(err) => {
            return Err(err.into());
        }
    };
    let secret_key = dotenvy::var("SECRET_KEY").expect("Secret key cannot be empty");
    let now = chrono::Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::minutes(1)).timestamp() as usize;
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        role: String,
        iat: usize,
        exp: usize,
    }
    // Generate a JWT token
    let claims = Claims {
        sub: public_key,
        role: "admin".to_string(),
        iat,
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
    .unwrap();

    Ok(token)
}
