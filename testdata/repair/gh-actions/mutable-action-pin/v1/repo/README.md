# chronodex

A small command-line utility that indexes timestamped log lines into a
queryable summary. Built with the Go standard library only.

## Build

```
make build
```

## Test

```
make test
```

Releases are produced by CI on version tags: the pipeline builds the
binary, runs the tests, and publishes the artifact.
