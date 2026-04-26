# Render deploy for `server1port`

This setup deploys `server1port` as a Render Web Service using Docker.

## Notes

- The service binds to `0.0.0.0:$PORT` at runtime, which matches Render's web service requirement.
- Set `AUTH_KEY` in Render as a secret environment variable before first deploy.
- `PORT` defaults to `10000`, which is Render's default expected HTTP port.
- Render terminates TLS at its edge. The app still listens with plain HTTP internally.
- WebSocket traffic should work through Render on the same public service URL.
- HTTP `CONNECT` support through Render's edge proxy is still a deployment risk and should be validated in the target environment.

## Blueprint path

This Blueprint file lives at `deploy/render/render.yaml`.
When creating the service from a Blueprint, point Render to this file instead of the repo-root default.
