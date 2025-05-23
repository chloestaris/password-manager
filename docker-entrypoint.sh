#!/bin/bash
set -e

# Initialize the database if it doesn't exist
if [ ! -f /app/data/password_manager.db ]; then
    echo "Initializing database..."
    # Create database and run migrations
    /app/sqlx database create
    /app/sqlx migrate run
fi

# Start the application
exec "$@" 