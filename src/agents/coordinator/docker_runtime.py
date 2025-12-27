from __future__ import annotations

import os
import platform
import posixpath
from typing import Optional


def _parse_bool_env(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _detect_platform() -> str:
    machine = platform.machine().lower()
    if "arm" in machine or "aarch64" in machine:
        return "linux/arm64"
    return "linux/amd64"


def _candidate_host_ports(base_port: int, max_attempts: int = 5) -> list[int]:
    return [base_port + offset for offset in range(max_attempts)]


def _is_port_unavailable_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        ("port" in message and "not available" in message)
        or "address already in use" in message
        or "port is already allocated" in message
        or "failed to bind" in message
    )


def _load_docker_workspace_classes():
    # Support both the new workspace module path and legacy SDK path.
    try:
        from openhands.workspace import DockerDevWorkspace, DockerWorkspace

        return DockerWorkspace, DockerDevWorkspace
    except ImportError:
        try:
            from openhands.sdk.workspace import DockerDevWorkspace, DockerWorkspace

            return DockerWorkspace, DockerDevWorkspace
        except ImportError:
            return None, None


def create_docker_workspace():
    # Build a DockerWorkspace with server image first, then fall back to base images/ports.
    docker_workspace_cls, docker_dev_cls = _load_docker_workspace_classes()
    if docker_workspace_cls is None:
        raise RuntimeError(
            "DockerWorkspace is unavailable; install a newer openhands-sdk that includes it."
        )

    extra_ports = _parse_bool_env(os.getenv("DOCKER_EXTRA_PORTS", "false"))
    base_image = os.getenv("DOCKER_BASE_IMAGE", "python:3.11-slim")
    server_image = os.getenv("DOCKER_SERVER_IMAGE", "").strip()
    try:
        host_port = int(os.getenv("DOCKER_HOST_PORT", "8010"))
    except ValueError as exc:
        raise RuntimeError("DOCKER_HOST_PORT must be an integer.") from exc
    docker_platform = _detect_platform()
    workspace_root = os.getenv("DOCKER_WORKSPACE_ROOT", "/workspace")

    # Candidate parameter sets; we iterate ports and signatures for compatibility.
    attempts: list[dict[str, object]] = []
    if server_image:
        attempts.append(
            {
                "server_image": server_image,
                "host_port": host_port,
                "platform": docker_platform,
                "extra_ports": extra_ports,
            }
        )
    attempts.append(
        {
            "server_image": "ghcr.io/openhands/agent-server:latest-python",
            "platform": docker_platform,
            "extra_ports": extra_ports,
        }
    )
    attempts.append(
        {
            "base_container_image": base_image,
            "workspace_mount_path": workspace_root,
            "extra_ports": extra_ports,
            "host_port": host_port,
        }
    )
    attempts.append({"base_container_image": base_image, "extra_ports": extra_ports})

    last_exc: Optional[Exception] = None
    for port in _candidate_host_ports(host_port):
        port_blocked = False
        for kwargs in attempts:
            candidate = dict(kwargs)
            if "host_port" in candidate:
                candidate["host_port"] = port
            try:
                return docker_workspace_cls(**candidate)
            except TypeError:
                if "host_port" in candidate:
                    candidate.pop("host_port", None)
                try:
                    return docker_workspace_cls(**candidate)
                except Exception as exc:
                    last_exc = exc
                    if _is_port_unavailable_error(exc):
                        port_blocked = True
                        break
                    continue
            except Exception as exc:
                last_exc = exc
                if _is_port_unavailable_error(exc):
                    port_blocked = True
                    break
                continue
        if port_blocked:
            continue

    if docker_dev_cls is not None:
        for port in _candidate_host_ports(host_port):
            try:
                return docker_dev_cls(
                    base_image=base_image,
                    host_port=port,
                    platform=docker_platform,
                    extra_ports=extra_ports,
                )
            except TypeError:
                try:
                    return docker_dev_cls(base_image=base_image)
                except Exception as exc:
                    last_exc = exc
                    if _is_port_unavailable_error(exc):
                        continue
                    break
            except Exception as exc:
                last_exc = exc
                if _is_port_unavailable_error(exc):
                    continue
                break

    if last_exc:
        raise RuntimeError(
            "Unable to initialize DockerWorkspace with available parameters. "
            f"Last error: {last_exc}"
        ) from last_exc
    raise RuntimeError("Unable to initialize DockerWorkspace with available parameters.")


def docker_paths(run_id: str) -> tuple[str, str, str, str]:
    workspace_root = os.getenv("DOCKER_WORKSPACE_ROOT", "/workspace")
    workspace_dir = posixpath.join(workspace_root, run_id)
    repo_dir = posixpath.join(workspace_dir, "repo")
    artifacts_dir = posixpath.join(workspace_dir, "artifacts")
    return workspace_root, workspace_dir, repo_dir, artifacts_dir


def docker_delegate_enabled() -> bool:
    return _parse_bool_env(os.getenv("DOCKER_ENABLE_DELEGATE", "false"))
