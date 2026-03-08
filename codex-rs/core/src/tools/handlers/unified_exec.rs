use crate::exec::ExecToolCallOutput;
use crate::exec::StreamOutput;
use crate::exec_policy::ExecApprovalRequest;
use crate::features::Feature;
use crate::function_tool::FunctionCallError;
use crate::is_safe_command::is_known_safe_command;
use crate::protocol::EventMsg;
use crate::protocol::TerminalInteractionEvent;
use crate::remote_workspace::RemoteExecRequest;
use crate::remote_workspace::RemoteExecResponse;
use crate::remote_workspace::RemoteUnifiedExecSessionState;
use crate::remote_workspace::RemoteWorkspaceClient;
use crate::remote_workspace::RemoteWriteStdinRequest;
use crate::sandboxing::SandboxPermissions;
use crate::shell::Shell;
use crate::shell::get_shell_by_model_provided_path;
use crate::skills::maybe_emit_implicit_skill_invocation;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::events::ToolEmitter;
use crate::tools::events::ToolEventCtx;
use crate::tools::events::ToolEventStage;
use crate::tools::handlers::apply_patch::intercept_apply_patch;
use crate::tools::handlers::normalize_and_validate_additional_permissions;
use crate::tools::handlers::parse_arguments;
use crate::tools::handlers::parse_arguments_with_base_path;
use crate::tools::handlers::resolve_workdir_base_path;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use crate::tools::runtimes::unified_exec::UnifiedExecApprovalKey;
use crate::tools::sandboxing::ExecApprovalRequirement;
use crate::tools::sandboxing::with_cached_approval;
use crate::truncate::TruncationPolicy;
use crate::truncate::approx_token_count;
use crate::truncate::formatted_truncate_text;
use crate::unified_exec::ExecCommandRequest;
use crate::unified_exec::UnifiedExecContext;
use crate::unified_exec::UnifiedExecProcessManager;
use crate::unified_exec::UnifiedExecResponse;
use crate::unified_exec::WriteStdinRequest;
use crate::unified_exec::generate_chunk_id;
use crate::unified_exec::resolve_max_tokens;
use async_trait::async_trait;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::NetworkPolicyRuleAction;
use codex_protocol::protocol::ReviewDecision;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

pub struct UnifiedExecHandler;

#[derive(Debug, Deserialize)]
pub(crate) struct ExecCommandArgs {
    cmd: String,
    #[serde(default)]
    pub(crate) workdir: Option<String>,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    login: Option<bool>,
    #[serde(default = "default_tty")]
    tty: bool,
    #[serde(default = "default_exec_yield_time_ms")]
    yield_time_ms: u64,
    #[serde(default)]
    max_output_tokens: Option<usize>,
    #[serde(default)]
    sandbox_permissions: SandboxPermissions,
    #[serde(default)]
    additional_permissions: Option<PermissionProfile>,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    prefix_rule: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct WriteStdinArgs {
    // The model is trained on `session_id`.
    session_id: i32,
    #[serde(default)]
    chars: String,
    #[serde(default = "default_write_stdin_yield_time_ms")]
    yield_time_ms: u64,
    #[serde(default)]
    max_output_tokens: Option<usize>,
}

fn default_exec_yield_time_ms() -> u64 {
    10000
}

fn default_write_stdin_yield_time_ms() -> u64 {
    250
}

fn default_tty() -> bool {
    false
}

#[async_trait]
impl ToolHandler for UnifiedExecHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(payload, ToolPayload::Function { .. })
    }

    async fn is_mutating(&self, invocation: &ToolInvocation) -> bool {
        let ToolPayload::Function { arguments } = &invocation.payload else {
            tracing::error!(
                "This should never happen, invocation payload is wrong: {:?}",
                invocation.payload
            );
            return true;
        };

        let Ok(params) = serde_json::from_str::<ExecCommandArgs>(arguments) else {
            return true;
        };
        let command = match get_command(
            &params,
            invocation.session.user_shell(),
            invocation.turn.tools_config.allow_login_shell,
        ) {
            Ok(command) => command,
            Err(_) => return true,
        };
        !is_known_safe_command(&command)
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            tracker,
            call_id,
            tool_name,
            payload,
            ..
        } = invocation;

        let arguments = match payload {
            ToolPayload::Function { arguments } => arguments,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "unified_exec handler received unsupported payload".to_string(),
                ));
            }
        };

        let manager: &UnifiedExecProcessManager = &session.services.unified_exec_manager;
        let context = UnifiedExecContext::new(session.clone(), turn.clone(), call_id.clone());

        let response = match tool_name.as_str() {
            "exec_command" => {
                let cwd = resolve_workdir_base_path(&arguments, context.turn.cwd.as_path())?;
                let args: ExecCommandArgs =
                    parse_arguments_with_base_path(&arguments, cwd.as_path())?;
                maybe_emit_implicit_skill_invocation(
                    session.as_ref(),
                    turn.as_ref(),
                    &args.cmd,
                    args.workdir.as_deref(),
                )
                .await;
                let process_id = manager.allocate_process_id().await;
                let command = get_command(
                    &args,
                    session.user_shell(),
                    turn.tools_config.allow_login_shell,
                )
                .map_err(FunctionCallError::RespondToModel)?;

                let ExecCommandArgs {
                    workdir,
                    tty,
                    yield_time_ms,
                    max_output_tokens,
                    sandbox_permissions,
                    additional_permissions,
                    justification,
                    prefix_rule,
                    ..
                } = args;

                let request_permission_enabled =
                    session.features().enabled(Feature::RequestPermissions);

                if sandbox_permissions.requests_sandbox_override()
                    && !matches!(
                        context.turn.approval_policy.value(),
                        codex_protocol::protocol::AskForApproval::OnRequest
                    )
                {
                    let approval_policy = context.turn.approval_policy.value();
                    manager.release_process_id(&process_id).await;
                    return Err(FunctionCallError::RespondToModel(format!(
                        "approval policy is {approval_policy:?}; reject command — you cannot ask for escalated permissions if the approval policy is {approval_policy:?}"
                    )));
                }

                let workdir = workdir.filter(|value| !value.is_empty());

                let workdir = workdir.map(|dir| context.turn.resolve_path(Some(dir)));
                let cwd = workdir.clone().unwrap_or(cwd);
                let normalized_additional_permissions =
                    match normalize_and_validate_additional_permissions(
                        request_permission_enabled,
                        context.turn.approval_policy.value(),
                        sandbox_permissions,
                        additional_permissions,
                        &cwd,
                    ) {
                        Ok(normalized) => normalized,
                        Err(err) => {
                            manager.release_process_id(&process_id).await;
                            return Err(FunctionCallError::RespondToModel(err));
                        }
                    };

                if let Some((client, workspace_id)) =
                    get_remote_workspace_binding(session.as_ref(), turn.as_ref())?
                {
                    let response = remote_exec_command(
                        client,
                        workspace_id,
                        &context,
                        &process_id,
                        command,
                        cwd,
                        yield_time_ms,
                        max_output_tokens,
                        tty,
                        sandbox_permissions,
                        normalized_additional_permissions,
                        justification,
                        prefix_rule,
                    )
                    .await?;
                    return Ok(ToolOutput::Function {
                        body: FunctionCallOutputBody::Text(format_response(&response)),
                        success: Some(true),
                    });
                }

                if let Some(output) = intercept_apply_patch(
                    &command,
                    &cwd,
                    Some(yield_time_ms),
                    context.session.clone(),
                    context.turn.clone(),
                    Some(&tracker),
                    &context.call_id,
                    tool_name.as_str(),
                )
                .await?
                {
                    manager.release_process_id(&process_id).await;
                    return Ok(output);
                }

                manager
                    .exec_command(
                        ExecCommandRequest {
                            command,
                            process_id,
                            yield_time_ms,
                            max_output_tokens,
                            workdir,
                            network: context.turn.network.clone(),
                            tty,
                            sandbox_permissions,
                            additional_permissions: normalized_additional_permissions,
                            justification,
                            prefix_rule,
                        },
                        &context,
                    )
                    .await
                    .map_err(|err| {
                        FunctionCallError::RespondToModel(format!("exec_command failed: {err:?}"))
                    })?
            }
            "write_stdin" => {
                let args: WriteStdinArgs = parse_arguments(&arguments)?;
                let response = if let Some((client, workspace_id)) =
                    get_remote_workspace_binding(session.as_ref(), turn.as_ref())?
                {
                    remote_write_stdin(
                        client,
                        workspace_id,
                        &context,
                        manager,
                        args.session_id.to_string(),
                        args.chars.clone(),
                        args.yield_time_ms,
                        args.max_output_tokens,
                    )
                    .await?
                } else {
                    manager
                        .write_stdin(WriteStdinRequest {
                            process_id: &args.session_id.to_string(),
                            input: &args.chars,
                            yield_time_ms: args.yield_time_ms,
                            max_output_tokens: args.max_output_tokens,
                        })
                        .await
                        .map_err(|err| {
                            FunctionCallError::RespondToModel(format!("write_stdin failed: {err}"))
                        })?
                };

                let interaction = TerminalInteractionEvent {
                    call_id: response.event_call_id.clone(),
                    process_id: args.session_id.to_string(),
                    stdin: args.chars.clone(),
                };
                session
                    .send_event(turn.as_ref(), EventMsg::TerminalInteraction(interaction))
                    .await;

                response
            }
            other => {
                return Err(FunctionCallError::RespondToModel(format!(
                    "unsupported unified exec function {other}"
                )));
            }
        };

        let content = format_response(&response);

        Ok(ToolOutput::Function {
            body: FunctionCallOutputBody::Text(content),
            success: Some(true),
        })
    }
}

pub(crate) fn get_command(
    args: &ExecCommandArgs,
    session_shell: Arc<Shell>,
    allow_login_shell: bool,
) -> Result<Vec<String>, String> {
    let model_shell = args.shell.as_ref().map(|shell_str| {
        let mut shell = get_shell_by_model_provided_path(&PathBuf::from(shell_str));
        shell.shell_snapshot = crate::shell::empty_shell_snapshot_receiver();
        shell
    });

    let shell = model_shell.as_ref().unwrap_or(session_shell.as_ref());
    let use_login_shell = match args.login {
        Some(true) if !allow_login_shell => {
            return Err(
                "login shell is disabled by config; omit `login` or set it to false.".to_string(),
            );
        }
        Some(use_login_shell) => use_login_shell,
        None => allow_login_shell,
    };

    Ok(shell.derive_exec_args(&args.cmd, use_login_shell))
}

fn format_response(response: &UnifiedExecResponse) -> String {
    let mut sections = Vec::new();

    if !response.chunk_id.is_empty() {
        sections.push(format!("Chunk ID: {}", response.chunk_id));
    }

    let wall_time_seconds = response.wall_time.as_secs_f64();
    sections.push(format!("Wall time: {wall_time_seconds:.4} seconds"));

    if let Some(exit_code) = response.exit_code {
        sections.push(format!("Process exited with code {exit_code}"));
    }

    if let Some(process_id) = &response.process_id {
        // Training still uses "session ID".
        sections.push(format!("Process running with session ID {process_id}"));
    }

    if let Some(original_token_count) = response.original_token_count {
        sections.push(format!("Original token count: {original_token_count}"));
    }

    sections.push("Output:".to_string());
    sections.push(response.output.clone());

    sections.join("\n")
}

fn get_remote_workspace_binding<'a>(
    session: &'a crate::codex::Session,
    turn: &'a crate::codex::TurnContext,
) -> Result<Option<(&'a Arc<RemoteWorkspaceClient>, &'a str)>, FunctionCallError> {
    match (
        session.services.remote_workspace_client.as_ref(),
        turn.remote_workspace
            .as_ref()
            .and_then(|workspace| workspace.workspace_id.as_deref()),
    ) {
        (Some(client), Some(workspace_id)) => Ok(Some((client, workspace_id))),
        (None, None) => Ok(None),
        _ => Err(FunctionCallError::RespondToModel(
            "remote workspace session is misconfigured".to_string(),
        )),
    }
}

fn remote_exec_output(response: &RemoteExecResponse) -> ExecToolCallOutput {
    let aggregated_output = if response.aggregated_output.is_empty() {
        format!("{}{}", response.stdout, response.stderr)
    } else {
        response.aggregated_output.clone()
    };

    ExecToolCallOutput {
        exit_code: response.exit_code.unwrap_or(0),
        stdout: StreamOutput::new(response.stdout.clone()),
        stderr: StreamOutput::new(response.stderr.clone()),
        aggregated_output: StreamOutput::new(aggregated_output),
        duration: response.wall_time,
        timed_out: false,
    }
}

fn remote_unified_exec_response(
    call_id: String,
    command: Vec<String>,
    response: RemoteExecResponse,
    max_output_tokens: Option<usize>,
) -> UnifiedExecResponse {
    let aggregated_output = if response.aggregated_output.is_empty() {
        format!("{}{}", response.stdout, response.stderr)
    } else {
        response.aggregated_output.clone()
    };
    let output = formatted_truncate_text(
        &aggregated_output,
        TruncationPolicy::Tokens(resolve_max_tokens(max_output_tokens)),
    );

    UnifiedExecResponse {
        event_call_id: call_id,
        chunk_id: generate_chunk_id(),
        wall_time: response.wall_time,
        output,
        raw_output: aggregated_output.as_bytes().to_vec(),
        process_id: response.process_id,
        exit_code: response.exit_code,
        original_token_count: Some(approx_token_count(&aggregated_output)),
        session_command: Some(command),
    }
}

async fn approve_remote_exec_command(
    context: &UnifiedExecContext,
    command: &[String],
    cwd: &PathBuf,
    tty: bool,
    sandbox_permissions: SandboxPermissions,
    additional_permissions: Option<PermissionProfile>,
    justification: Option<String>,
    prefix_rule: Option<Vec<String>>,
) -> Result<(), FunctionCallError> {
    let requirement = context
        .session
        .services
        .exec_policy
        .create_exec_approval_requirement_for_command(ExecApprovalRequest {
            command,
            approval_policy: context.turn.approval_policy.value(),
            sandbox_policy: context.turn.sandbox_policy.get(),
            sandbox_permissions,
            prefix_rule,
        })
        .await;

    match requirement {
        ExecApprovalRequirement::Skip { .. } => Ok(()),
        ExecApprovalRequirement::Forbidden { reason } => {
            Err(FunctionCallError::RespondToModel(reason))
        }
        ExecApprovalRequirement::NeedsApproval {
            reason,
            proposed_execpolicy_amendment,
        } => {
            let keys = vec![UnifiedExecApprovalKey {
                command: command.to_vec(),
                cwd: cwd.clone(),
                tty,
                sandbox_permissions,
                additional_permissions: additional_permissions.clone(),
            }];
            let session = context.session.clone();
            let session_for_request = context.session.clone();
            let turn = context.turn.clone();
            let call_id = context.call_id.clone();
            let approval_reason = reason.or_else(|| justification.clone());
            let decision = with_cached_approval(
                &session.services,
                "unified_exec",
                keys,
                move || async move {
                    session_for_request
                        .request_command_approval(
                            turn.as_ref(),
                            call_id,
                            None,
                            command.to_vec(),
                            cwd.clone(),
                            approval_reason,
                            None,
                            proposed_execpolicy_amendment,
                            additional_permissions,
                            None,
                        )
                        .await
                },
            )
            .await;

            match decision {
                ReviewDecision::Approved
                | ReviewDecision::ApprovedExecpolicyAmendment { .. }
                | ReviewDecision::ApprovedForSession => Ok(()),
                ReviewDecision::Denied | ReviewDecision::Abort => Err(
                    FunctionCallError::RespondToModel("exec command rejected by user".to_string()),
                ),
                ReviewDecision::NetworkPolicyAmendment {
                    network_policy_amendment,
                } => match network_policy_amendment.action {
                    NetworkPolicyRuleAction::Allow => Ok(()),
                    NetworkPolicyRuleAction::Deny => Err(FunctionCallError::RespondToModel(
                        "exec command rejected by user".to_string(),
                    )),
                },
            }
        }
    }
}

async fn remote_exec_command(
    client: &RemoteWorkspaceClient,
    workspace_id: &str,
    context: &UnifiedExecContext,
    process_id: &str,
    command: Vec<String>,
    cwd: PathBuf,
    yield_time_ms: u64,
    max_output_tokens: Option<usize>,
    tty: bool,
    sandbox_permissions: SandboxPermissions,
    additional_permissions: Option<PermissionProfile>,
    justification: Option<String>,
    prefix_rule: Option<Vec<String>>,
) -> Result<UnifiedExecResponse, FunctionCallError> {
    approve_remote_exec_command(
        context,
        &command,
        &cwd,
        tty,
        sandbox_permissions,
        additional_permissions,
        justification,
        prefix_rule,
    )
    .await?;

    let response = client
        .exec_command(RemoteExecRequest {
            workspace_id: workspace_id.to_string(),
            process_id: process_id.to_string(),
            command: command.clone(),
            workdir: Some(cwd.clone()),
            yield_time_ms,
            max_output_tokens,
            tty,
        })
        .await
        .map_err(|err| FunctionCallError::RespondToModel(format!("exec_command failed: {err}")))?;

    let event_process_id = response
        .process_id
        .clone()
        .unwrap_or_else(|| process_id.to_string());
    let event_ctx = ToolEventCtx::new(
        context.session.as_ref(),
        context.turn.as_ref(),
        &context.call_id,
        None,
    );
    let emitter = ToolEmitter::unified_exec(
        &command,
        cwd.clone(),
        crate::protocol::ExecCommandSource::UnifiedExecStartup,
        Some(event_process_id.clone()),
    );
    emitter.begin(event_ctx).await;

    if response.process_id.is_some() && response.exit_code.is_none() {
        let mut sessions = context
            .session
            .services
            .remote_unified_exec_sessions
            .lock()
            .await;
        sessions.insert(
            event_process_id.clone(),
            RemoteUnifiedExecSessionState {
                call_id: context.call_id.clone(),
                command: command.clone(),
                cwd,
            },
        );
        if event_process_id != process_id {
            context
                .session
                .services
                .unified_exec_manager
                .release_process_id(process_id)
                .await;
        }
    } else {
        context
            .session
            .services
            .unified_exec_manager
            .release_process_id(process_id)
            .await;
        emitter
            .emit(
                event_ctx,
                ToolEventStage::Success(remote_exec_output(&response)),
            )
            .await;
    }

    Ok(remote_unified_exec_response(
        context.call_id.clone(),
        command,
        response,
        max_output_tokens,
    ))
}

async fn remote_write_stdin(
    client: &RemoteWorkspaceClient,
    workspace_id: &str,
    context: &UnifiedExecContext,
    manager: &UnifiedExecProcessManager,
    process_id: String,
    input: String,
    yield_time_ms: u64,
    max_output_tokens: Option<usize>,
) -> Result<UnifiedExecResponse, FunctionCallError> {
    let response = client
        .write_stdin(RemoteWriteStdinRequest {
            workspace_id: workspace_id.to_string(),
            process_id: process_id.clone(),
            input: input.clone(),
            yield_time_ms,
            max_output_tokens,
        })
        .await
        .map_err(|err| FunctionCallError::RespondToModel(format!("write_stdin failed: {err}")))?;

    let mut sessions = context
        .session
        .services
        .remote_unified_exec_sessions
        .lock()
        .await;
    let state = sessions.get(&process_id).cloned();
    if response.process_id.is_none() || response.exit_code.is_some() {
        sessions.remove(&process_id);
    }
    drop(sessions);

    if response.process_id.is_none() || response.exit_code.is_some() {
        manager.release_process_id(&process_id).await;
        if let Some(state) = state.as_ref() {
            let event_ctx = ToolEventCtx::new(
                context.session.as_ref(),
                context.turn.as_ref(),
                &state.call_id,
                None,
            );
            let emitter = ToolEmitter::unified_exec(
                &state.command,
                state.cwd.clone(),
                crate::protocol::ExecCommandSource::UnifiedExecStartup,
                Some(process_id.clone()),
            );
            emitter
                .emit(
                    event_ctx,
                    ToolEventStage::Success(remote_exec_output(&response)),
                )
                .await;
        }
    }

    Ok(remote_unified_exec_response(
        state
            .as_ref()
            .map(|state| state.call_id.clone())
            .unwrap_or_else(|| context.call_id.clone()),
        state
            .as_ref()
            .map(|state| state.command.clone())
            .unwrap_or_default(),
        response,
        max_output_tokens,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::make_session_and_context_with_rx;
    use crate::protocol::AskForApproval;
    use crate::remote_workspace::RemoteWorkspaceConfig;
    use crate::remote_workspace::RemoteWorkspaceSession;
    use crate::shell::default_user_shell;
    use crate::tools::context::ToolOutput;
    use crate::tools::handlers::parse_arguments_with_base_path;
    use crate::tools::handlers::resolve_workdir_base_path;
    use crate::turn_diff_tracker::TurnDiffTracker;
    use crate::unified_exec::set_deterministic_process_ids_for_tests;
    use codex_protocol::models::FileSystemPermissions;
    use codex_protocol::models::PermissionProfile;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Mutex;
    use wiremock::matchers::method;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_get_command_uses_default_shell_when_unspecified() -> anyhow::Result<()> {
        let json = r#"{"cmd": "echo hello"}"#;

        let args: ExecCommandArgs = parse_arguments(json)?;

        assert!(args.shell.is_none());

        let command =
            get_command(&args, Arc::new(default_user_shell()), true).map_err(anyhow::Error::msg)?;

        assert_eq!(command.len(), 3);
        assert_eq!(command[2], "echo hello");
        Ok(())
    }

    #[test]
    fn test_get_command_respects_explicit_bash_shell() -> anyhow::Result<()> {
        let json = r#"{"cmd": "echo hello", "shell": "/bin/bash"}"#;

        let args: ExecCommandArgs = parse_arguments(json)?;

        assert_eq!(args.shell.as_deref(), Some("/bin/bash"));

        let command =
            get_command(&args, Arc::new(default_user_shell()), true).map_err(anyhow::Error::msg)?;

        assert_eq!(command.last(), Some(&"echo hello".to_string()));
        if command
            .iter()
            .any(|arg| arg.eq_ignore_ascii_case("-Command"))
        {
            assert!(command.contains(&"-NoProfile".to_string()));
        }
        Ok(())
    }

    #[test]
    fn test_get_command_respects_explicit_powershell_shell() -> anyhow::Result<()> {
        let json = r#"{"cmd": "echo hello", "shell": "powershell"}"#;

        let args: ExecCommandArgs = parse_arguments(json)?;

        assert_eq!(args.shell.as_deref(), Some("powershell"));

        let command =
            get_command(&args, Arc::new(default_user_shell()), true).map_err(anyhow::Error::msg)?;

        assert_eq!(command[2], "echo hello");
        Ok(())
    }

    #[test]
    fn test_get_command_respects_explicit_cmd_shell() -> anyhow::Result<()> {
        let json = r#"{"cmd": "echo hello", "shell": "cmd"}"#;

        let args: ExecCommandArgs = parse_arguments(json)?;

        assert_eq!(args.shell.as_deref(), Some("cmd"));

        let command =
            get_command(&args, Arc::new(default_user_shell()), true).map_err(anyhow::Error::msg)?;

        assert_eq!(command[2], "echo hello");
        Ok(())
    }

    #[test]
    fn test_get_command_rejects_explicit_login_when_disallowed() -> anyhow::Result<()> {
        let json = r#"{"cmd": "echo hello", "login": true}"#;

        let args: ExecCommandArgs = parse_arguments(json)?;
        let err = get_command(&args, Arc::new(default_user_shell()), false)
            .expect_err("explicit login should be rejected");

        assert!(
            err.contains("login shell is disabled by config"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn exec_command_args_resolve_relative_additional_permissions_against_workdir()
    -> anyhow::Result<()> {
        let cwd = tempdir()?;
        let workdir = cwd.path().join("nested");
        fs::create_dir_all(&workdir)?;
        let expected_write = workdir.join("relative-write.txt");
        let json = r#"{
            "cmd": "echo hello",
            "workdir": "nested",
            "additional_permissions": {
                "file_system": {
                    "write": ["./relative-write.txt"]
                }
            }
        }"#;

        let base_path = resolve_workdir_base_path(json, cwd.path())?;
        let args: ExecCommandArgs = parse_arguments_with_base_path(json, base_path.as_path())?;

        assert_eq!(
            args.additional_permissions,
            Some(PermissionProfile {
                file_system: Some(FileSystemPermissions {
                    read: None,
                    write: Some(vec![AbsolutePathBuf::try_from(expected_write)?]),
                }),
                ..Default::default()
            })
        );
        Ok(())
    }

    fn output_text(output: ToolOutput) -> String {
        match output {
            ToolOutput::Function { body, .. } => body.to_text().unwrap_or_default(),
            ToolOutput::Mcp { .. } => panic!("expected function output"),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn unified_exec_handler_uses_remote_workspace_for_exec_and_stdin() -> anyhow::Result<()> {
        set_deterministic_process_ids_for_tests(true);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/workspaces/ws_1/exec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "process_id": "1000",
                "exit_code": null,
                "stdout": "hi\n",
                "stderr": "",
                "aggregated_output": "hi\n",
                "wall_time_ms": 12
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/workspaces/ws_1/processes/1000/stdin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "process_id": null,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "aggregated_output": "",
                "wall_time_ms": 8
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

        let (mut session, mut turn, _rx) = make_session_and_context_with_rx().await;
        Arc::get_mut(&mut session)
            .expect("session is uniquely owned")
            .services
            .remote_workspace_client = Some(Arc::new(client));

        let turn_mut = Arc::get_mut(&mut turn).expect("turn is uniquely owned");
        turn_mut
            .approval_policy
            .set(AskForApproval::Never)
            .expect("test setup should allow updating approval policy");
        turn_mut.remote_workspace = Some(RemoteWorkspaceSession {
            config: config.clone(),
            workspace_id: Some("ws_1".to_string()),
        });

        let handler = UnifiedExecHandler;
        let tracker = Arc::new(Mutex::new(TurnDiffTracker::new()));

        let exec_output = handler
            .handle(ToolInvocation {
                session: session.clone(),
                turn: turn.clone(),
                tracker: tracker.clone(),
                call_id: "call_exec".to_string(),
                tool_name: "exec_command".to_string(),
                payload: ToolPayload::Function {
                    arguments: r#"{"cmd":"echo hi","yield_time_ms":250}"#.to_string(),
                },
            })
            .await?;
        let exec_text = output_text(exec_output);
        assert!(exec_text.contains("Process running with session ID 1000"));

        let sessions = session.services.remote_unified_exec_sessions.lock().await;
        assert!(sessions.contains_key("1000"));
        drop(sessions);

        let stdin_output = handler
            .handle(ToolInvocation {
                session: session.clone(),
                turn: turn.clone(),
                tracker,
                call_id: "call_stdin".to_string(),
                tool_name: "write_stdin".to_string(),
                payload: ToolPayload::Function {
                    arguments: r#"{"session_id":1000,"chars":"exit\n","yield_time_ms":5000}"#
                        .to_string(),
                },
            })
            .await?;
        let stdin_text = output_text(stdin_output);
        assert!(stdin_text.contains("Process exited with code 0"));

        let sessions = session.services.remote_unified_exec_sessions.lock().await;
        assert!(sessions.is_empty());

        set_deterministic_process_ids_for_tests(false);
        Ok(())
    }
}
