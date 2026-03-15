#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd "${script_dir}/.." && pwd)"
readonly image_tag="${SERVAL_INTEGRATION_IMAGE:-serval-integration:local}"
readonly dockerfile_path="${repo_root}/integration/Dockerfile"
readonly zig_version="0.16.0-dev.2821+3edaef9e0"
readonly zig_archive_name="zig-x86_64-linux-${zig_version}.tar.xz"
readonly local_zig_dir_default="/usr/local/zig-x86_64-linux-${zig_version}"
readonly local_zig_dir="${SERVAL_CUSTOM_ZIG_DIR:-${local_zig_dir_default}}"
readonly local_zig_archive_default="/usr/local/${zig_archive_name}"
readonly local_zig_archive="${SERVAL_CUSTOM_ZIG_ARCHIVE:-${local_zig_archive_default}}"
readonly default_command="zig build -Doptimize=ReleaseFast && zig build test -Doptimize=ReleaseFast && zig build test-integration -Doptimize=ReleaseFast && integration/h2_conformance_ci.sh --h2spec-timeout 1"
readonly docker_security_opt="${SERVAL_DOCKER_SECURITY_OPT:-seccomp=unconfined}"
readonly docker_memlock_ulimit="${SERVAL_DOCKER_MEMLOCK_ULIMIT:-memlock=-1}"
readonly docker_cap_add="${SERVAL_DOCKER_CAP_ADD:-IPC_LOCK}"
readonly docker_context_excludes=(
    ".git"
    ".zig-cache"
    "zig-cache"
    "zig-out"
    ".claude"
    ".entire"
    ".tmp_stdlib"
    "zig-pkg"
    "sframe_test"
    "DEPLOY.md"
    "Makefile"
)

if [[ $# -eq 0 ]]; then
    command=(bash -lc "${default_command}")
else
    command=("$@")
fi

temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT

build_context="${temp_dir}/context"

rsync_args=(--archive --delete)
for path in "${docker_context_excludes[@]}"; do
    rsync_args+=(--exclude "${path}")
done
rsync "${rsync_args[@]}" "${repo_root}/" "${build_context}/"

mkdir -p "${build_context}/integration/toolchains"

if [[ -d "${local_zig_dir}" ]]; then
    tar -C "$(dirname "${local_zig_dir}")" -cJf \
        "${build_context}/integration/toolchains/${zig_archive_name}" \
        "$(basename "${local_zig_dir}")"
elif [[ -f "${local_zig_archive}" ]]; then
    cp "${local_zig_archive}" "${build_context}/integration/toolchains/${zig_archive_name}"
else
    echo "missing custom Zig toolchain" >&2
    echo "expected directory: ${local_zig_dir}" >&2
    echo "or archive: ${local_zig_archive}" >&2
    echo "set SERVAL_CUSTOM_ZIG_DIR or SERVAL_CUSTOM_ZIG_ARCHIVE explicitly" >&2
    exit 1
fi

docker build -f "${dockerfile_path}" -t "${image_tag}" "${build_context}"

docker run --rm \
    --security-opt "${docker_security_opt}" \
    --ulimit "${docker_memlock_ulimit}" \
    --cap-add "${docker_cap_add}" \
    -v "${repo_root}:/work/serval" \
    -v serval-go-build-cache:/var/cache/serval/go-build \
    -v serval-go-mod-cache:/var/cache/serval/go-mod \
    -v serval-zig-global-cache:/var/cache/serval/zig-global \
    -w /work/serval \
    "${image_tag}" \
    "${command[@]}"
