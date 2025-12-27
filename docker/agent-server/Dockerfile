FROM ghcr.io/openhands/agent-server:latest-python

USER root

# Ensure agent-server Python modules exist so sitecustomize can import DelegateTool.
RUN python -m pip install --no-cache-dir \
    openhands-agent-server==1.7.1 \
    openhands-tools==1.7.1 \
    openhands-workspace==1.7.1

# sitecustomize runs on interpreter startup to preload DelegateTool + Fixer agent.
COPY sitecustomize.py /tmp/sitecustomize.py
RUN python - <<'PY'
import shutil
import site

dst = site.getsitepackages()[0] + "/sitecustomize.py"
shutil.copy("/tmp/sitecustomize.py", dst)
print(f"Installed {dst}")
PY

USER openhands

ENTRYPOINT ["python", "-m", "openhands.agent_server"]
