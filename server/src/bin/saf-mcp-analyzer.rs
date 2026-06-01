use server::SafMcpServer;

use rmcp::{service::QuitReason, transport, ServiceExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Expose tools over stdio transport for MCP clients (e.g., Cursor, Claude Desktop).
    let server = SafMcpServer::new();
    let running = server
        .serve(transport::stdio())
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
    match running.waiting().await {
        Ok(QuitReason::Closed) => Ok(()),
        Ok(QuitReason::Cancelled) => Ok(()),
        Ok(QuitReason::JoinError(e)) => Err(Box::<dyn std::error::Error>::from(e)),
        Err(e) => Err(Box::<dyn std::error::Error>::from(e)),
    }
}
