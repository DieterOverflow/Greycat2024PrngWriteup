# Solution script
We have a dockerfile for the solution.

## Build
```
docker build -t prg . 
```

## Test against Server
```
docker run -it prg
```

## Test Locally
```
docker run -it prg python solve-prg.py LOCAL
```

