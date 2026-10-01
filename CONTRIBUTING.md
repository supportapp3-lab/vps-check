# Contributing

Issues, bug reports, and feature requests are welcome. Please describe the environment and steps to reproduce a problem, and avoid posting private server details or secrets.

Before opening a pull request, run:

```sh
go test ./...
go vet ./...
go build ./...
```

Keep changes focused and preserve the read-only behavior of `vps-check`.
