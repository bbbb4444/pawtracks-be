#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

# Take the Base64-encoded variable, decode it, and write it to a temporary file in the container.
# We'll use /app/credentials.json as the location within the container.
echo $GOOGLE_APPLICATION_CREDENTIALS | base64 -d > /app/credentials.json

# CRITICAL STEP: Unset the old variable and re-export it with the *path* to the new file.
# Google's client libraries will now automatically detect and use this file.
export GOOGLE_APPLICATION_CREDENTIALS=/app/credentials.json

# Execute the original command passed to the container (e.g., `java -jar app.jar`).
# This starts your actual application.
exec "$@"