use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::get,
    Router,
};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    // 0.0.0.0:port
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);
    // 定义共享内存
    let state = HttpServeState { path: path.clone() };
    // axum router 匹配path, method, 设置method handler
    // axum默认不支持正则匹配, 需要用*path或者:path的方式匹配然后通过Path extractor提取
    // 使用Arc::new 共享一个实例
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/{*path}", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, HeaderMap, String) {
    let mut header_map = HeaderMap::new();
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);

    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            header_map,
            format!("File {} not found", p.display()), // display()实现了Display trait
        )
    } else {
        // 支持预览目录, 返回html
        if p.is_dir() {
            let mut files = Vec::new();
            let mut entries = tokio::fs::read_dir(&p).await.unwrap();
            while let Some(entry) = entries.next_entry().await.unwrap() {
                let file_name = entry.file_name();
                files.push(file_name.to_string_lossy().into_owned());
            }
            let mut html_list = Vec::new();
            html_list.push("<ul>".to_string());
            for file_name in files {
                let li = format!(
                    r#"
                <li><a href="{}/{}">{}</a></li>
                "#,
                    std::fs::canonicalize(&p)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                        .replace(env::current_dir().unwrap().to_str().unwrap(), ""),
                    file_name,
                    file_name
                );

                html_list.push(li);
            }
            html_list.push("</ul>".to_string());
            header_map.insert("Content-Type", HeaderValue::from_static("text/html"));
            (StatusCode::OK, header_map, html_list.join(""))
        } else {
            // tokio::fs提供异步文件系统
            match tokio::fs::read_to_string(p).await {
                Ok(content) => {
                    info!("Read {} bytes", content.len());
                    (StatusCode::OK, header_map, content)
                }
                Err(e) => {
                    warn!("Error reading file: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, header_map, e.to_string())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });

        let (status, _, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package]"));
    }
}
