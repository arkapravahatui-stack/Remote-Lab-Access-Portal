# Remote Lab Access Portal

A browser-based remote lab terminal that allows users to access a remote machine through an SSH gateway.

## Current Progress

### Step 1 - Browser Terminal
- Browser-based terminal interface
- xterm.js terminal
- WebSocket communication
- Nginx frontend serving

### Step 2 - Gateway Bridge & SSH Connection
- FastAPI backend
- Uvicorn ASGI server
- WebSocket endpoint
- AsyncSSH integration
- SSH key authentication
- Interactive SSH shell
- Nginx reverse proxy
- Clean WebSocket/SSH session cleanup

## Architecture

Browser (xterm.js)
        |
        | WebSocket
        v
Nginx Reverse Proxy
        |
        v
FastAPI / Uvicorn
        |
        | AsyncSSH
        v
SSH Lab Machine

## Project Structure

Remote-Lab-Access-Portal/
├── frontend/
│   └── index.html
├── backend/
│   ├── main.py
│   ├── ssh_test.py
│   └── ssh_terminal.py
├── nginx/
│   └── nginx.conf
├── requirements.txt
├── README.md
└── .gitignore

## Installation

Create a virtual environment:

    python3 -m venv backend/venv

Activate it on macOS/Linux:

    source backend/venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Running the Backend

    cd backend
    uvicorn main:app --reload

The FastAPI backend runs at:

    http://127.0.0.1:8000

## Nginx

The project contains the working Nginx configuration in:

    nginx/nginx.conf

Nginx serves the frontend and proxies WebSocket traffic to the FastAPI backend.

The portal can then be opened at:

    http://127.0.0.1:8080

## SSH Configuration

The current prototype uses localhost as the SSH target for development and testing.

For deployment, configure the backend with the authorized lab machine's:

- SSH hostname/IP
- SSH username
- SSH key

Never commit private SSH keys, passwords, tokens, or `.env` files to this repository.

## Current Architecture Status

Step 1: Complete

Step 2: Complete

Next: Step 3 - Authentication, Session Management and Idle Timeout