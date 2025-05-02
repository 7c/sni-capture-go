# Release
for cross-platform release i am using docker to build

## build the image
```bash
docker build -t goreleaser-builder .
```

## run the container
docker run --rm -it -v $(pwd):/app -v $(pwd)/dist:/dist goreleaser-builder