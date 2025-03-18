from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime
import random

# Import our custom modules
from fake_model import predict_attack
from data_generator import generate_fake_attack

app = FastAPI(title="AI Attack Detection API", 
              description="API for simulated AI-powered cyber attack detection")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store attack history (in-memory)
attack_history = []

# Define data models
class LogData(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    timestamp: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, Any]] = None
    url_path: Optional[str] = None
    method: Optional[str] = None

class AttackResponse(BaseModel):
    attack_detected: bool
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    confidence_score: Optional[float] = None
    timestamp: str
    recommendation: Optional[str] = None

class AttackLog(BaseModel):
    id: str
    timestamp: str
    ip: str
    attack_type: str
    severity: str
    status: str
    details: Optional[Dict[str, Any]] = None

@app.post("/detect-attack", response_model=AttackResponse)
async def detect_attack(log_data: LogData):
    # Use our fake model to "analyze" the logs
    prediction = predict_attack(log_data.dict())
    
    # Format the response
    response = AttackResponse(
        attack_detected=prediction["attack_detected"],
        attack_type=prediction["attack_type"],
        severity=prediction["severity"],
        confidence_score=prediction["confidence_score"],
        timestamp=datetime.now().isoformat(),
        recommendation=prediction.get("recommendation")
    )
    
    # If attack detected, save to history
    if prediction["attack_detected"]:
        attack_log = AttackLog(
            id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            ip=log_data.source_ip,
            attack_type=prediction["attack_type"],
            severity=prediction["severity"],
            status="Active",
            details=log_data.dict()
        )
        attack_history.append(attack_log.dict())
    
    return response

@app.get("/fake-attacks", response_model=List[AttackLog])
async def get_fake_attacks(count: int = 10):
    """
    Generate and return a list of fake attack logs
    """
    fake_attacks = []
    
    # If we have existing attack history, include some of them
    if attack_history and random.random() > 0.5:
        # Include some historical attacks (up to half the requested count)
        historical_count = min(len(attack_history), count // 2)
        fake_attacks.extend(random.sample(attack_history, historical_count))
    
    # Generate additional fake attacks to meet the requested count
    additional_needed = count - len(fake_attacks)
    for _ in range(additional_needed):
        fake_attack = generate_fake_attack()
        fake_attacks.append(fake_attack)
    
    return fake_attacks

@app.get("/attack-history", response_model=List[AttackLog])
async def get_attack_history():
    """
    Return the full attack history (attacks detected through the API)
    """
    return attack_history

@app.post("/reset-history")
async def reset_history():
    """
    Clear the attack history
    """
    global attack_history
    attack_history = []
    return {"message": "Attack history cleared"}

@app.get("/health")
async def health_check():
    """
    Simple health check endpoint
    """
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)