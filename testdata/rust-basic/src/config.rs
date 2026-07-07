use std::env;

pub struct Config {
    pub allowed_groups: Vec<String>,
    pub email_domain: String,
    pub debug: bool,
    pub secret_key: String,
    pub database_url: String,
}

pub fn get_config() -> Config {
    Config {
        allowed_groups: vec![],
        email_domain: "*".to_string(),
        debug: true,
        secret_key: env::var("SECRET_KEY").unwrap_or_else(|_| "changeme".to_string()),
        database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://localhost/mydb?sslmode=disable".to_string()),
    }
}
