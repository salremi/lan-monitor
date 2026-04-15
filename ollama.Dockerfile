FROM ollama/ollama:latest

# Expose the Ollama port
EXPOSE 11434

# Set the working directory
WORKDIR /app

# Copy the Ollama model configuration
# This is a simplified example - in practice, you would pull the model you need
# RUN ollama pull llama3.2

# Start Ollama server
CMD ["ollama", "serve"]
