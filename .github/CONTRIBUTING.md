# CONTRIBUTING

Any PullRequest for the better is welcome!

- Branch to PR: `main`
- Issues:
  - Please include a simple code snippet to reproduce the issue. It will help us a lot to fix the issue.
  - Issues can be in Japanese and Spanish rather than English if you prefer.

## Tests and CIs

You need to pass the below before review.

- `go test -race ./...` on Go 1.15 ~ latest
- `golangci-lint run`: see the `.golangci.yml` for the configuration
- `golint ./...`
- Keeping 100% of code coverage

We have CIs to check these. So we recommend to [draft PR](https://github.blog/2019-02-14-introducing-draft-pull-requests/) before you implement something.

For convenience, there is a `docker-compose.yml` for the above.

```bash
# Run test on Go 1.15
docker compose run v1_16

# Run test on Go 1.19
docker compose run v1_19

# Run test on latest Go
docker compose run latest

# Run linters (golangci-lint)
docker compose run lint
```
