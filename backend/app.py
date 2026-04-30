from fastapi import FastAPI
from pydantic import BaseModel
from backend.predict import predict_message

app = FastAPI()

class Message(BaseModel):
    text: str

@app.get("/")
def home():
    return {"message": "AI Phishing Detector API Running"}

@app.post("/predict")
def predict(msg: Message):
    label, confidence, url_score = predict_message(msg.text)
    return {
        "label": label,
        "confidence": confidence,
        "url_score": url_score
    }