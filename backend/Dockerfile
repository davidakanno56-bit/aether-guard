# Use a minimal, secure base image
FROM python:3.11-slim

# Prevent Python from writing bytecode and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Create a dedicated, unprivileged system user and group
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup --no-create-home appuser

# Copy dependency specifications and install dependencies before copying app code
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend files and set ownership to unprivileged user
COPY --chown=appuser:appgroup . .

# Switch to the unprivileged user
USER appuser

# Expose the application port
EXPOSE 8000

# Run FastAPI using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
