# Release
for cross-platform release i am using docker to build

## build the image
```bash
docker build -t goreleaser-builder .
```

## run the container to build and deploy to github,you need to have GITHUB_TOKEN taken from github https://github.com/settings/tokens/new
```bash
docker run --rm -it -e GITHUB_TOKEN -v $(pwd):/app -v $(pwd)/dist:/dist goreleaser-builder
```
