// pub mod utils;
pub mod transaction_handler;
pub mod network_handler;
pub mod token_address_handler;
use crate::utils;

use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::sync::Arc;
use axum::{http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
}, Router};
use tower_http::cors::CorsLayer;
use crate::routers::{
    transaction_routes::transaction_routes,
    network_routes::network_routes,
    token_address_routes::token_address_routes,
};

pub struct AppState {
    db: Pool<Postgres>,
}

pub async fn start() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
    {
        Ok(pool) => {
            println!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

    let cors = CorsLayer::new()
    .allow_origin("http://localhost:8000".parse::<HeaderValue>().unwrap())
    .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
    .allow_credentials(true)
    .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);
    
    // database::transact(pool.clone()).await?;
    let app = Router::new()
        .merge(transaction_routes(Arc::new(AppState { db: pool.clone() })))
        .merge(network_routes(Arc::new(AppState { db: pool.clone() })))
        .merge(token_address_routes(Arc::new(AppState { db: pool.clone() })))
        .layer(cors);


    println!("🚀 Server started successfully");

    
    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}