#!/bin/sh

# Check and create 'evoting' DB if it doesn't exist
echo "Checking if database '$DB_NAME' exists..."

if PGPASSWORD=$POSTGRES_PASSWORD psql -h db -U postgres -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
  echo "Database '$DB_NAME' already exists."
else
  echo "Database '$DB_NAME' not found. Creating it..."
  PGPASSWORD=$POSTGRES_PASSWORD createdb -h db -U postgres $DB_NAME
fi

# Start the Node.js app
node server.js
