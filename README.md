# Chirpy

Chirpy is a lightweight, Twitter-inspired microblogging platform built as part of the [Boot.dev](https://boot.dev) course. It allows users to create accounts, log in, and post short messages (chirps) with a character limit of 140. The project is designed to demonstrate backend development concepts, including authentication, database integration, and RESTful API design.

## Features

- **User Authentication**: Secure user registration and login with hashed passwords and JWT-based authentication.
- **Post Chirps**: Users can post short messages (chirps) with a maximum length of 140 characters.
- **Token Expiration**: Configurable token expiration with a default of 1 hour.
- **Error Handling**: Comprehensive error handling for invalid input, authentication failures, and more.
- **Database Integration**: Persistent storage of users and chirps using a relational database.

## Technologies Used

- **Go**: The primary programming language for the backend.
- **JWT (JSON Web Tokens)**: For secure user authentication and session management.
- **bcrypt**: For password hashing and verification.
- **PostgreSQL**: Relational database for storing user and chirp data.
- **Docker** (optional): For containerized deployment.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/5tuartw/chirpy.git
   cd chirpy
   ```
2.  **Set Up Environment Variables**: Create a .env file in the root directory with the following variables:
```bash
JWT_SECRET=your_jwt_secret
DB_URL=your_db_url
PLATFORM="dev"
```
3. **Install Dependencies**: Ensure you have Go installed, then run:
```bash
go mod tidy
```
4. **Run the application**
```bash
go run main.go
```
5. **Access the API**
## API Endpoints
### Authentication
- POST /login
    - Request Body:
```json
{
  "email": "user@example.com",
  "password": "your_password",
  "expires_in_seconds": 3600
}
```
    - Response:
```json
{
  "id": "user-id",
  "email": "user@example.com",
  "token": "jwt-token"
}
```
### Chirps
- POST /chirps
    - Request Body:
```json
{
  "body": "This is a chirp!"
}
```
    - Response:
```json
{
  "id": "chirp-id",
  "body": "This is a chirp!",
  "user_id": "user-id",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments
This project was developed as part of the Boot.dev course. Special thanks to the Boot.dev team for their guidance and resources.