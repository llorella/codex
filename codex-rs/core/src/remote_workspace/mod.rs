use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::default_client::build_reqwest_client;

const DEFAULT_PROVIDER: &str = "http";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteWorkspaceImportMode {
    #[default]
    Copy,
    GitClone,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteWorkspaceExportMode {
    #[default]
    Patch,
    Branch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteWorkspaceProviderKind {
    Http,
}

impl RemoteWorkspaceProviderKind {
    fn parse(provider: Option<&str>) -> Result<Self, RemoteWorkspaceError> {
        match provider.unwrap_or(DEFAULT_PROVIDER) {
            "http" => Ok(Self::Http),
            other => Err(RemoteWorkspaceError::UnsupportedProvider(other.to_string())),
        }
    }
}

/// Configuration for a remote-authoritative coding workspace.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct RemoteWorkspaceConfig {
    /// Enables remote-authoritative workspace mode for the session.
    #[serde(default)]
    pub enabled: bool,
    /// Optional provider/backend identifier used by the remote workspace API.
    pub provider: Option<String>,
    /// Base URL for the remote workspace control plane.
    pub base_url: Option<String>,
    /// Optional template or image identifier used to provision the workspace.
    pub template: Option<String>,
    /// Optional environment variable name containing a bearer token.
    pub auth_token_env_var: Option<String>,
    /// How the local repo should be imported into the remote workspace.
    #[serde(default)]
    pub import_mode: RemoteWorkspaceImportMode,
    /// How remote changes should be exported back to the caller.
    #[serde(default)]
    pub export_mode: RemoteWorkspaceExportMode,
}

impl RemoteWorkspaceConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn provider_kind(&self) -> Result<RemoteWorkspaceProviderKind, RemoteWorkspaceError> {
        RemoteWorkspaceProviderKind::parse(self.provider.as_deref())
    }

    pub fn validate(&self) -> Result<(), RemoteWorkspaceError> {
        if !self.enabled {
            return Ok(());
        }

        let _provider = self.provider_kind()?;
        if self.base_url.as_deref().is_none_or(str::is_empty) {
            return Err(RemoteWorkspaceError::MissingBaseUrl);
        }

        if let Some(env_var) = self.auth_token_env_var.as_deref() {
            let token =
                env::var(env_var).map_err(|source| RemoteWorkspaceError::MissingAuthToken {
                    env_var: env_var.to_string(),
                    source,
                })?;
            if token.trim().is_empty() {
                return Err(RemoteWorkspaceError::EmptyAuthToken(env_var.to_string()));
            }
        }

        Ok(())
    }
}

/// Session-scoped binding for a remote workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteWorkspaceSession {
    pub config: RemoteWorkspaceConfig,
    pub workspace_id: Option<String>,
}

impl RemoteWorkspaceSession {
    pub fn new(config: RemoteWorkspaceConfig) -> Self {
        Self {
            config,
            workspace_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteWorkspaceBinding {
    pub workspace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExecRequest {
    pub workspace_id: String,
    pub process_id: String,
    pub command: Vec<String>,
    pub workdir: Option<PathBuf>,
    pub yield_time_ms: u64,
    pub max_output_tokens: Option<usize>,
    pub tty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteWriteStdinRequest {
    pub workspace_id: String,
    pub process_id: String,
    pub input: String,
    pub yield_time_ms: u64,
    pub max_output_tokens: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExecResponse {
    pub process_id: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub aggregated_output: String,
    pub wall_time: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUnifiedExecSessionState {
    pub call_id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReadFileIndentationRequest {
    pub anchor_line: Option<usize>,
    pub max_levels: usize,
    pub include_siblings: bool,
    pub include_header: bool,
    pub max_lines: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReadFileRequest {
    pub workspace_id: String,
    pub file_path: String,
    pub offset: usize,
    pub limit: usize,
    pub mode: String,
    pub indentation: Option<RemoteReadFileIndentationRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReadFileResponse {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteListDirRequest {
    pub workspace_id: String,
    pub dir_path: String,
    pub offset: usize,
    pub limit: usize,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteListDirResponse {
    pub absolute_path: String,
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGrepFilesRequest {
    pub workspace_id: String,
    pub pattern: String,
    pub include: Option<String>,
    pub path: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGrepFilesResponse {
    pub matches: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApplyPatchRequest {
    pub workspace_id: String,
    pub patch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApplyPatchResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub wall_time: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExportPatchRequest {
    pub workspace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExportPatchResponse {
    pub unified_diff: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRemoteWorkspaceRequest {
    pub session_id: String,
    pub cwd: PathBuf,
    pub template: Option<String>,
    pub import_mode: RemoteWorkspaceImportMode,
    pub export_mode: RemoteWorkspaceExportMode,
}

#[derive(Debug, Error)]
pub enum RemoteWorkspaceError {
    #[error("remote workspace provider `{0}` is unsupported")]
    UnsupportedProvider(String),

    #[error("remote workspace mode requires `base_url`")]
    MissingBaseUrl,

    #[error("environment variable `{env_var}` for remote workspace auth token is missing")]
    MissingAuthToken {
        env_var: String,
        #[source]
        source: env::VarError,
    },

    #[error("environment variable `{0}` for remote workspace auth token is empty")]
    EmptyAuthToken(String),

    #[error("remote workspace request failed with status {status}: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },

    #[error("remote workspace HTTP request failed")]
    Http(#[from] reqwest::Error),

    #[error("remote workspace JSON response was invalid")]
    Json(#[from] serde_json::Error),
}

#[async_trait]
pub trait RemoteWorkspaceProvider: Send + Sync {
    async fn bind_session(
        &self,
        request: BindRemoteWorkspaceRequest,
    ) -> Result<RemoteWorkspaceBinding, RemoteWorkspaceError>;

    async fn exec_command(
        &self,
        request: RemoteExecRequest,
    ) -> Result<RemoteExecResponse, RemoteWorkspaceError>;

    async fn write_stdin(
        &self,
        request: RemoteWriteStdinRequest,
    ) -> Result<RemoteExecResponse, RemoteWorkspaceError>;

    async fn read_file(
        &self,
        request: RemoteReadFileRequest,
    ) -> Result<RemoteReadFileResponse, RemoteWorkspaceError>;

    async fn list_dir(
        &self,
        request: RemoteListDirRequest,
    ) -> Result<RemoteListDirResponse, RemoteWorkspaceError>;

    async fn grep_files(
        &self,
        request: RemoteGrepFilesRequest,
    ) -> Result<RemoteGrepFilesResponse, RemoteWorkspaceError>;

    async fn apply_patch(
        &self,
        request: RemoteApplyPatchRequest,
    ) -> Result<RemoteApplyPatchResponse, RemoteWorkspaceError>;

    async fn export_patch(
        &self,
        request: RemoteExportPatchRequest,
    ) -> Result<RemoteExportPatchResponse, RemoteWorkspaceError>;
}

#[derive(Clone)]
pub struct RemoteWorkspaceClient {
    provider: Arc<dyn RemoteWorkspaceProvider>,
}

impl RemoteWorkspaceClient {
    pub fn from_config(
        config: &RemoteWorkspaceConfig,
    ) -> Result<Option<Self>, RemoteWorkspaceError> {
        if !config.is_enabled() {
            return Ok(None);
        }

        config.validate()?;
        let provider: Arc<dyn RemoteWorkspaceProvider> = match config.provider_kind()? {
            RemoteWorkspaceProviderKind::Http => {
                Arc::new(HttpRemoteWorkspaceProvider::new(config)?)
            }
        };
        Ok(Some(Self { provider }))
    }

    pub async fn bind_session(
        &self,
        request: BindRemoteWorkspaceRequest,
    ) -> Result<RemoteWorkspaceBinding, RemoteWorkspaceError> {
        self.provider.bind_session(request).await
    }

    pub async fn exec_command(
        &self,
        request: RemoteExecRequest,
    ) -> Result<RemoteExecResponse, RemoteWorkspaceError> {
        self.provider.exec_command(request).await
    }

    pub async fn write_stdin(
        &self,
        request: RemoteWriteStdinRequest,
    ) -> Result<RemoteExecResponse, RemoteWorkspaceError> {
        self.provider.write_stdin(request).await
    }

    pub async fn read_file(
        &self,
        request: RemoteReadFileRequest,
    ) -> Result<RemoteReadFileResponse, RemoteWorkspaceError> {
        self.provider.read_file(request).await
    }

    pub async fn list_dir(
        &self,
        request: RemoteListDirRequest,
    ) -> Result<RemoteListDirResponse, RemoteWorkspaceError> {
        self.provider.list_dir(request).await
    }

    pub async fn grep_files(
        &self,
        request: RemoteGrepFilesRequest,
    ) -> Result<RemoteGrepFilesResponse, RemoteWorkspaceError> {
        self.provider.grep_files(request).await
    }

    pub async fn apply_patch(
        &self,
        request: RemoteApplyPatchRequest,
    ) -> Result<RemoteApplyPatchResponse, RemoteWorkspaceError> {
        self.provider.apply_patch(request).await
    }

    pub async fn export_patch(
        &self,
        request: RemoteExportPatchRequest,
    ) -> Result<RemoteExportPatchResponse, RemoteWorkspaceError> {
        self.provider.export_patch(request).await
    }
}

#[derive(Debug)]
struct HttpRemoteWorkspaceProvider {
    base_url: String,
    auth_token: Option<String>,
    http: reqwest::Client,
}

impl HttpRemoteWorkspaceProvider {
    fn new(config: &RemoteWorkspaceConfig) -> Result<Self, RemoteWorkspaceError> {
        config.validate()?;
        let auth_token = config
            .auth_token_env_var
            .as_deref()
            .map(env::var)
            .transpose()
            .map_err(|source| RemoteWorkspaceError::MissingAuthToken {
                env_var: config.auth_token_env_var.clone().unwrap_or_default(),
                source,
            })?;

        Ok(Self {
            base_url: config
                .base_url
                .clone()
                .expect("validated remote workspace base_url"),
            auth_token,
            http: build_reqwest_client(),
        })
    }
}

#[derive(Serialize)]
struct HttpBindSessionRequest {
    session_id: String,
    cwd: String,
    template: Option<String>,
    import_mode: RemoteWorkspaceImportMode,
    export_mode: RemoteWorkspaceExportMode,
}

#[derive(Deserialize)]
struct HttpBindSessionResponse {
    workspace_id: String,
}

#[derive(Serialize)]
struct HttpExecCommandRequest {
    process_id: String,
    command: Vec<String>,
    workdir: Option<String>,
    yield_time_ms: u64,
    max_output_tokens: Option<usize>,
    tty: bool,
}

#[derive(Serialize)]
struct HttpWriteStdinRequest {
    input: String,
    yield_time_ms: u64,
    max_output_tokens: Option<usize>,
}

#[derive(Serialize)]
struct HttpReadFileIndentationRequest {
    anchor_line: Option<usize>,
    max_levels: usize,
    include_siblings: bool,
    include_header: bool,
    max_lines: Option<usize>,
}

#[derive(Serialize)]
struct HttpReadFileRequest {
    file_path: String,
    offset: usize,
    limit: usize,
    mode: String,
    indentation: Option<HttpReadFileIndentationRequest>,
}

#[derive(Deserialize)]
struct HttpReadFileResponse {
    lines: Vec<String>,
}

#[derive(Serialize)]
struct HttpListDirRequest {
    dir_path: String,
    offset: usize,
    limit: usize,
    depth: usize,
}

#[derive(Deserialize)]
struct HttpListDirResponse {
    absolute_path: String,
    entries: Vec<String>,
}

#[derive(Serialize)]
struct HttpGrepFilesRequest {
    pattern: String,
    include: Option<String>,
    path: Option<String>,
    limit: usize,
}

#[derive(Deserialize)]
struct HttpGrepFilesResponse {
    matches: Vec<String>,
}

#[derive(Serialize)]
struct HttpApplyPatchRequest {
    patch: String,
}

#[derive(Deserialize)]
struct HttpApplyPatchResponse {
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    exit_code: i32,
    wall_time_ms: u64,
}

#[derive(Deserialize)]
struct HttpExportPatchResponse {
    #[serde(default)]
    unified_diff: Option<String>,
}

#[derive(Deserialize)]
struct HttpExecResponse {
    #[serde(default)]
    process_id: Option<String>,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    aggregated_output: String,
    wall_time_ms: u64,
}

#[async_trait]
impl RemoteWorkspaceProvider for HttpRemoteWorkspaceProvider {
    async fn bind_session(
        &self,
        request: BindRemoteWorkspaceRequest,
    ) -> Result<RemoteWorkspaceBinding, RemoteWorkspaceError> {
        let url = format!("{}/workspaces/session", self.base_url.trim_end_matches('/'));
        let payload = HttpBindSessionRequest {
            session_id: request.session_id,
            cwd: request.cwd.to_string_lossy().into_owned(),
            template: request.template,
            import_mode: request.import_mode,
            export_mode: request.export_mode,
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpBindSessionResponse = serde_json::from_str(&body)?;
        Ok(RemoteWorkspaceBinding {
            workspace_id: response.workspace_id,
        })
    }

    async fn exec_command(
        &self,
        request: RemoteExecRequest,
    ) -> Result<RemoteExecResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/exec",
            self.base_url.trim_end_matches('/'),
            request.workspace_id
        );
        let payload = HttpExecCommandRequest {
            process_id: request.process_id,
            command: request.command,
            workdir: request
                .workdir
                .map(|path| path.to_string_lossy().into_owned()),
            yield_time_ms: request.yield_time_ms,
            max_output_tokens: request.max_output_tokens,
            tty: request.tty,
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpExecResponse = serde_json::from_str(&body)?;
        Ok(RemoteExecResponse {
            process_id: response.process_id,
            exit_code: response.exit_code,
            stdout: response.stdout,
            stderr: response.stderr,
            aggregated_output: response.aggregated_output,
            wall_time: Duration::from_millis(response.wall_time_ms),
        })
    }

    async fn write_stdin(
        &self,
        request: RemoteWriteStdinRequest,
    ) -> Result<RemoteExecResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/processes/{}/stdin",
            self.base_url.trim_end_matches('/'),
            request.workspace_id,
            request.process_id
        );
        let payload = HttpWriteStdinRequest {
            input: request.input,
            yield_time_ms: request.yield_time_ms,
            max_output_tokens: request.max_output_tokens,
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpExecResponse = serde_json::from_str(&body)?;
        Ok(RemoteExecResponse {
            process_id: response.process_id,
            exit_code: response.exit_code,
            stdout: response.stdout,
            stderr: response.stderr,
            aggregated_output: response.aggregated_output,
            wall_time: Duration::from_millis(response.wall_time_ms),
        })
    }

    async fn read_file(
        &self,
        request: RemoteReadFileRequest,
    ) -> Result<RemoteReadFileResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/read_file",
            self.base_url.trim_end_matches('/'),
            request.workspace_id
        );
        let payload = HttpReadFileRequest {
            file_path: request.file_path,
            offset: request.offset,
            limit: request.limit,
            mode: request.mode,
            indentation: request
                .indentation
                .map(|indentation| HttpReadFileIndentationRequest {
                    anchor_line: indentation.anchor_line,
                    max_levels: indentation.max_levels,
                    include_siblings: indentation.include_siblings,
                    include_header: indentation.include_header,
                    max_lines: indentation.max_lines,
                }),
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpReadFileResponse = serde_json::from_str(&body)?;
        Ok(RemoteReadFileResponse {
            lines: response.lines,
        })
    }

    async fn list_dir(
        &self,
        request: RemoteListDirRequest,
    ) -> Result<RemoteListDirResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/list_dir",
            self.base_url.trim_end_matches('/'),
            request.workspace_id
        );
        let payload = HttpListDirRequest {
            dir_path: request.dir_path,
            offset: request.offset,
            limit: request.limit,
            depth: request.depth,
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpListDirResponse = serde_json::from_str(&body)?;
        Ok(RemoteListDirResponse {
            absolute_path: response.absolute_path,
            entries: response.entries,
        })
    }

    async fn grep_files(
        &self,
        request: RemoteGrepFilesRequest,
    ) -> Result<RemoteGrepFilesResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/grep_files",
            self.base_url.trim_end_matches('/'),
            request.workspace_id
        );
        let payload = HttpGrepFilesRequest {
            pattern: request.pattern,
            include: request.include,
            path: request.path,
            limit: request.limit,
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpGrepFilesResponse = serde_json::from_str(&body)?;
        Ok(RemoteGrepFilesResponse {
            matches: response.matches,
        })
    }

    async fn apply_patch(
        &self,
        request: RemoteApplyPatchRequest,
    ) -> Result<RemoteApplyPatchResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/apply_patch",
            self.base_url.trim_end_matches('/'),
            request.workspace_id
        );
        let payload = HttpApplyPatchRequest {
            patch: request.patch,
        };

        let mut http_request = self.http.post(url).json(&payload);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpApplyPatchResponse = serde_json::from_str(&body)?;
        Ok(RemoteApplyPatchResponse {
            stdout: response.stdout,
            stderr: response.stderr,
            exit_code: response.exit_code,
            wall_time: Duration::from_millis(response.wall_time_ms),
        })
    }

    async fn export_patch(
        &self,
        request: RemoteExportPatchRequest,
    ) -> Result<RemoteExportPatchResponse, RemoteWorkspaceError> {
        let url = format!(
            "{}/workspaces/{}/export_patch",
            self.base_url.trim_end_matches('/'),
            request.workspace_id
        );

        let mut http_request = self.http.get(url);
        if let Some(token) = self.auth_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }

        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(RemoteWorkspaceError::UnexpectedStatus { status, body });
        }

        let response: HttpExportPatchResponse = serde_json::from_str(&body)?;
        Ok(RemoteExportPatchResponse {
            unified_diff: response.unified_diff.filter(|diff| !diff.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::body_json;
    use wiremock::matchers::header;
    use wiremock::matchers::method;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn http_provider_binds_workspace() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/session"))
            .and(body_json(serde_json::json!({
                "session_id": "thread-123",
                "cwd": "/workspace/repo",
                "template": "ubuntu-rust",
                "import_mode": "copy",
                "export_mode": "patch"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspace_id": "ws_123"
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            template: Some("ubuntu-rust".to_string()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let binding = client
            .bind_session(BindRemoteWorkspaceRequest {
                session_id: "thread-123".to_string(),
                cwd: PathBuf::from("/workspace/repo"),
                template: config.template.clone(),
                import_mode: config.import_mode,
                export_mode: config.export_mode,
            })
            .await?;

        assert_eq!(
            binding,
            RemoteWorkspaceBinding {
                workspace_id: "ws_123".to_string()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_sends_bearer_token_when_configured() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let token_env = "CODEX_REMOTE_WORKSPACE_TEST_TOKEN";
        let token_value = "secret-token";
        unsafe { env::set_var(token_env, token_value) };

        Mock::given(method("POST"))
            .and(path("/workspaces/session"))
            .and(header("authorization", format!("Bearer {token_value}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspace_id": "ws_auth"
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            auth_token_env_var: Some(token_env.to_string()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let binding = client
            .bind_session(BindRemoteWorkspaceRequest {
                session_id: "thread-456".to_string(),
                cwd: PathBuf::from("/workspace/repo"),
                template: None,
                import_mode: config.import_mode,
                export_mode: config.export_mode,
            })
            .await?;

        assert_eq!(binding.workspace_id, "ws_auth");
        unsafe { env::remove_var(token_env) };
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_execs_command() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_exec/exec"))
            .and(body_json(serde_json::json!({
                "process_id": "1234",
                "command": ["bash", "-lc", "echo hi"],
                "workdir": "/workspace/repo",
                "yield_time_ms": 250,
                "max_output_tokens": 500,
                "tty": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "process_id": "1234",
                "exit_code": null,
                "stdout": "hi\n",
                "stderr": "",
                "aggregated_output": "hi\n",
                "wall_time_ms": 42
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .exec_command(RemoteExecRequest {
                workspace_id: "ws_exec".to_string(),
                process_id: "1234".to_string(),
                command: vec!["bash".to_string(), "-lc".to_string(), "echo hi".to_string()],
                workdir: Some(PathBuf::from("/workspace/repo")),
                yield_time_ms: 250,
                max_output_tokens: Some(500),
                tty: true,
            })
            .await?;

        assert_eq!(response.process_id.as_deref(), Some("1234"));
        assert_eq!(response.exit_code, None);
        assert_eq!(response.aggregated_output, "hi\n");
        assert_eq!(response.wall_time, Duration::from_millis(42));
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_writes_stdin() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_exec/processes/1234/stdin"))
            .and(body_json(serde_json::json!({
                "input": "exit\n",
                "yield_time_ms": 5000,
                "max_output_tokens": 200
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "process_id": null,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "aggregated_output": "",
                "wall_time_ms": 17
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .write_stdin(RemoteWriteStdinRequest {
                workspace_id: "ws_exec".to_string(),
                process_id: "1234".to_string(),
                input: "exit\n".to_string(),
                yield_time_ms: 5_000,
                max_output_tokens: Some(200),
            })
            .await?;

        assert_eq!(response.process_id, None);
        assert_eq!(response.exit_code, Some(0));
        assert_eq!(response.wall_time, Duration::from_millis(17));
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_reads_file() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_read/read_file"))
            .and(body_json(serde_json::json!({
                "file_path": "/workspace/repo/src/lib.rs",
                "offset": 5,
                "limit": 20,
                "mode": "slice",
                "indentation": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lines": ["L5: fn main() {"]
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .read_file(RemoteReadFileRequest {
                workspace_id: "ws_read".to_string(),
                file_path: "/workspace/repo/src/lib.rs".to_string(),
                offset: 5,
                limit: 20,
                mode: "slice".to_string(),
                indentation: None,
            })
            .await?;

        assert_eq!(response.lines, vec!["L5: fn main() {".to_string()]);
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_lists_directory() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_dir/list_dir"))
            .and(body_json(serde_json::json!({
                "dir_path": "/workspace/repo/src",
                "offset": 1,
                "limit": 25,
                "depth": 2
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "absolute_path": "/workspace/repo/src",
                "entries": ["main.rs", "nested/"]
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .list_dir(RemoteListDirRequest {
                workspace_id: "ws_dir".to_string(),
                dir_path: "/workspace/repo/src".to_string(),
                offset: 1,
                limit: 25,
                depth: 2,
            })
            .await?;

        assert_eq!(response.absolute_path, "/workspace/repo/src");
        assert_eq!(
            response.entries,
            vec!["main.rs".to_string(), "nested/".to_string()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_greps_files() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_grep/grep_files"))
            .and(body_json(serde_json::json!({
                "pattern": "alpha",
                "include": "*.rs",
                "path": "/workspace/repo",
                "limit": 10
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "matches": ["/workspace/repo/src/lib.rs"]
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .grep_files(RemoteGrepFilesRequest {
                workspace_id: "ws_grep".to_string(),
                pattern: "alpha".to_string(),
                include: Some("*.rs".to_string()),
                path: Some("/workspace/repo".to_string()),
                limit: 10,
            })
            .await?;

        assert_eq!(
            response.matches,
            vec!["/workspace/repo/src/lib.rs".to_string()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_applies_patch() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_patch/apply_patch"))
            .and(body_json(serde_json::json!({
                "patch": "*** Begin Patch\n*** Add File: note.txt\n+hello\n*** End Patch\n"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "stdout": "applied",
                "stderr": "",
                "exit_code": 0,
                "wall_time_ms": 11
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .apply_patch(RemoteApplyPatchRequest {
                workspace_id: "ws_patch".to_string(),
                patch: "*** Begin Patch\n*** Add File: note.txt\n+hello\n*** End Patch\n"
                    .to_string(),
            })
            .await?;

        assert_eq!(response.stdout, "applied");
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.wall_time, Duration::from_millis(11));
        Ok(())
    }

    #[tokio::test]
    async fn http_provider_exports_patch() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/workspaces/ws_patch/export_patch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "unified_diff": "diff --git a/src/main.rs b/src/main.rs\n"
            })))
            .mount(&server)
            .await;

        let config = RemoteWorkspaceConfig {
            enabled: true,
            base_url: Some(server.uri()),
            ..Default::default()
        };
        let client = RemoteWorkspaceClient::from_config(&config)?
            .expect("enabled remote workspace should create a client");
        let response = client
            .export_patch(RemoteExportPatchRequest {
                workspace_id: "ws_patch".to_string(),
            })
            .await?;

        assert_eq!(
            response,
            RemoteExportPatchResponse {
                unified_diff: Some("diff --git a/src/main.rs b/src/main.rs\n".to_string()),
            }
        );
        Ok(())
    }
}
