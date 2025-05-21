# Password Manager API

A secure REST API for managing encrypted passwords and website credentials built with Rust.

## Features

- Secure password storage using AES-256-GCM encryption
- RESTful API endpoints for managing credentials
- SQLite database for data persistence
- Docker support for easy deployment

## Setup

1. Clone the repository
2. Create a `.env` file with the following variables:
   ```
   DATABASE_URL=sqlite:password_manager.db
   ENCRYPTION_KEY=<your-32-byte-encryption-key>
   RUST_LOG=debug
   ```
   
   To generate a secure encryption key, you can use:
   ```bash
   openssl rand -base64 32
   ```

3. Build and run with Docker:
   ```bash
   docker-compose up --build
   ```

## API Endpoints

### Create Credential
```
POST /credentials
Content-Type: application/json

{
    "website": "example.com",
    "username": "user@example.com",
    "password": "secretpassword"
}
```

### Get All Credentials
```
GET /credentials
```

### Get Credential by ID
```
GET /credentials/{id}
```

## Security Notes

- The API uses AES-256-GCM for password encryption
- Passwords are encrypted before storage
- The encryption key is never stored in the database
- All API responses exclude the actual password data
- Use HTTPS in production

## Development

To run in development mode:
```bash
docker-compose up
```

The API will be available at `http://localhost:8080` # password-manager
