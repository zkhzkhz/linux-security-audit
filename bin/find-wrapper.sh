#!/bin/bash
# Wrapper around /usr/bin/find that automatically prunes docker/containerd overlay paths.
# Used to prevent linpeas from hanging on hosts with many container layers.
exec /usr/bin/find "$@" \
  -not -path '*/overlay2/*' \
  -not -path '*/docker/*' \
  -not -path '*/containerd/*' \
  -not -path '*/var/snap/docker/*' \
  -not -path '*/run/snap.docker/*' \
  -not -path '*/.npm/_cacache/*'
