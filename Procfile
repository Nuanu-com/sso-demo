# Port 3001, because the Nuanu auth service runs on 8000 and running both at
# once is the point of the local setup.
web: GOFLAGS=-buildvcs=false air -c .air.toml serve -- -p 3001
vite: bun vite
