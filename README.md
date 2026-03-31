# Todoer - Task Management Application

A full-featured task management application with file management, built with Node.js, Express, and SQLite.

## Features

- Task management with priorities and due dates
- File upload and management
- Archive extraction support (.zip, .rar, .7z, .tar, .gz)
- User authentication and authorization
- Profile management (email, password, account deletion)
- Search functionality for tasks and files
- Responsive design

## Quick Start with Docker

### Prerequisites
- Docker
- Docker Compose

### Run the Application

```bash
docker-compose up --build
```

The application will be available at `http://localhost:3000`

### Stop the Application

```bash
docker-compose down
```

### Rebuild and Restart

```bash
docker-compose up --build
```

## Manual Installation (Without Docker)

### Prerequisites
- Node.js 20+
- npm

### Setup

```bash
npm install
node server.js
```

The application will be available at `http://localhost:3000`

## Usage

1. Register a new account or login
2. Manage your tasks on the Home page
3. Upload and manage files on the Files page
4. Update your profile on the Profile page

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/me` - Get current user

### Tasks
- `GET /api/tasks` - Get all tasks (supports search, filter, sort)
- `POST /api/tasks` - Create new task
- `PUT /api/tasks/:id` - Update task
- `DELETE /api/tasks/:id` - Delete task

### Files
- `GET /api/files` - Get all files
- `POST /api/files/upload` - Upload file
- `GET /api/files/:id/download` - Download file
- `POST /api/files/extract/:id` - Extract archive
- `POST /api/files/create-archive` - Create archive
- `DELETE /api/files/:id` - Delete file

### Profile
- `GET /api/profile` - Get profile
- `PUT /api/profile/email` - Update email
- `PUT /api/profile/password` - Change password
- `DELETE /api/profile/account` - Delete account

## Environment Variables

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment mode (development/production)

## License

MIT
