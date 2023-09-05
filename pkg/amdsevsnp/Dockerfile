# Use Alpine Linux as a lightweight base image
FROM alpine:latest

# Set the working directory within the container
WORKDIR /app

# Copy the executable file into the container
COPY amdsevsnp.test /app/amdsevsnp.test

# Make the executable file executable (if needed)
RUN chmod +x /app/amdsevsnp.test

# Define the command to run when the container starts
CMD ["/app/amdsevsnp.test"]

