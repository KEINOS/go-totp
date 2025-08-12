# CONTRIBUTING

Any PullRequest for the better is welcome!

- Branch to PR: `main`
- Issues:
  - Please include a simple code snippet to reproduce the issue. It will help us a lot to fix the issue.
  - Issues can be in Japanese and Spanish rather than English if you prefer.

## Tests and CIs

You need to pass the below before review.

- `go test -race ./...`
- `golangci-lint run`: see the `.golangci.yml` for the configuration
- `golint ./...`
- Keeping the current code coverage (if possible)

We have CIs to check these. So we recommend to [draft PR](https://github.blog/2019-02-14-introducing-draft-pull-requests/) before you implement something.

For convenience, there is a `docker-compose.yml` for the above.

```bash
# Preparation
docker compose build

# To run test on minimum supported Go version:
docker compose run --rm min

# To run test on latest Go:
docker compose run --rm latest

# To run linters (golangci-lint):
docker compose run --rm lint

# To run vulnerability check:
docker compose run --rm vuln
```
