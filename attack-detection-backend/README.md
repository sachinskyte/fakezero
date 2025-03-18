# AI-Powered Attack Detection Server

This is a simulated AI-powered cyber attack detection system built with FastAPI. It provides endpoints for detecting attacks and generating fake attack data for testing and demonstration purposes.

## Features

- AI-simulated attack detection
- Fake attack data generation
- RESTful API with FastAPI
- Configurable attack scenarios

## File Structure

```
/attack-detection-backend
│── /server
│   ├── app.py                 # Main FastAPI server
│   ├── fake_model.py          # Simulated AI model for attack detection
│   ├── data_generator.py      # Generates fake attack data
│   ├── requirements.txt       # Dependencies (FastAPI, Faker, etc.)
│── README.md                  # Setup instructions
```

## Installation

1. Clone this repository
2. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

### Running the Server

Start the server with:

```bash
cd server
uvicorn app:app --reload
```

The server will be available at `http://localhost:8000`.

### API Documentation

Once the server is running, you can access the Swagger UI documentation at:

`http://localhost:8000/docs`

### API Endpoints

- `POST /detect-attack`: Accepts log data and returns attack detection results
- `GET /fake-attacks`: Returns a list of simulated attack logs
- `GET /attack-history`: Returns previously detected attacks
- `POST /reset-history`: Clears the attack history
- `GET /health`: Simple health check endpoint

## Example Requests

### Detecting an attack

```bash
curl -X POST "http://localhost:8000/detect-attack" \
     -H "Content-Type: application/json" \
     -d '{
           "source_ip": "203.0.113.1",
           "destination_ip": "192.168.1.10",
           "timestamp": "2023-03-15T14:30:00",
           "request_data": {
             "query": "SELECT * FROM users WHERE username='' OR 1=1 --'"
           },
           "headers": {
             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
           },
           "url_path": "/login",
           "method": "POST"
         }'
```

### Getting fake attack logs

```bash
curl "http://localhost:8000/fake-attacks?count=5"
```

## Integration

This server can be integrated with a frontend dashboard for visualization of attack data. The API is CORS-enabled to support this integration.