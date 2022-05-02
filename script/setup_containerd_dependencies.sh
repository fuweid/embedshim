#!/usr/bin/env bash

set -euo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." > /dev/null 2>&1; pwd -P)"

# FIXME(fuweid):
#
# Since new release doesn't come out, use pinned v1.5.12 to install dependencies.
# In the future, I think we should maintain the scripts.
readonly CONTAINERD_COMMIT=v1.5.11

readonly TMP_DIR="$(mktemp -d)"

download_containerd_release() {
  local url
  url="https://github.com/containerd/containerd/archive/refs/tags/${CONTAINERD_COMMIT}.tar.gz"

  cd "${TMP_DIR}"
  wget "${url}"
  tar -xf "${CONTAINERD_COMMIT}.tar.gz"
  mkdir -p "${TMP_DIR}/src/github.com/containerd"
  mv containerd-${CONTAINERD_COMMIT:1:20} ${TMP_DIR}/src/github.com/containerd/containerd
  rm "${CONTAINERD_COMMIT}.tar.gz"
}

install_dependencies() {
  cd ${TMP_DIR}/src/github.com/containerd/containerd



  export GOPATH=${TMP_DIR}
  sudo -E PATH=$PATH script/setup/install-seccomp
  sudo -E PATH=$PATH script/setup/install-runc
  sudo -E PATH=$PATH script/setup/install-cni
  sudo -E PATH=$PATH script/setup/install-critools

  make bin/ctr
  sudo install bin/ctr /usr/local/bin
}

cleanup() {
  sudo rm -rf "${TMP_DIR}"
}

download_containerd_release

install_dependencies

cleanup
