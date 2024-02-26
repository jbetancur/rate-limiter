# Use a base image with a Linux distribution
FROM ubuntu:latest

ENV INTERFACE "ens33"

# Copy your eBPF program and loader script into the container
COPY rate-limiter .

# Make the loader script executable
RUN chmod +x rate-limiter

# Define the entry point for the container
ENTRYPOINT ["./rate-limiter"]
