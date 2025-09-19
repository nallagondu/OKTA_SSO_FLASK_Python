# Architecture

```mermaid
graph TD
    Dev[Developer] -->|Push Code| GitHub[GitHub Repo]
    GitHub --> CI[CI/CD Workflow]
    CI --> Deploy[Server/Cluster]
    Deploy --> Users[End Users]
